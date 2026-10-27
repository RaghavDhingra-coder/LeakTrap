"""Bounded public-domain evidence collection with fail-closed networking.

DNS lookups use a fixed DNS-over-HTTPS resolver. Website requests are pinned to
public IPs obtained from that resolver, use TLS, and follow only same-domain
HTTPS redirects. Only public domain evidence is eligible for Gemini analysis.
"""
from __future__ import annotations

import html
import ipaddress
import json
import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.client import HTTPResponse
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from backend.models import DomainEvidenceCache
from backend.services.domains import normalize_domain

logger = logging.getLogger("leaktrace.domain_evidence")
DOH_ENDPOINT = "https://dns.google/resolve"
MAX_DOH_BYTES = 16 * 1024
MAX_HTML_BYTES = 64 * 1024
MAX_REDIRECTS = 2
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
CACHE_TTL_SECONDS = 24 * 60 * 60
EVIDENCE_VERSION = 3
SELECTORS = ("default", "google", "selector1", "selector2")


class EvidenceError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _log_failure(stage: str, domain: str, code: str, correlation_id: str | None = None) -> None:
    logger.warning("domain_evidence stage=%s domain=%s category=%s correlation_id=%s",
                   stage, domain, code, correlation_id or "unavailable")


class _MetadataParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = []
        self.in_title = False
        self.meta: dict[str, str] = {}
        self.json_ld: list[str] = []
        self.in_json_ld = False
        self.script_data: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "meta":
            key = (values.get("property") or values.get("name") or "").lower()
            content = values.get("content", "")
            if key in {"og:site_name", "og:title", "description", "application-name"} and content:
                self.meta[key] = content[:500]
        if tag == "script" and values.get("type", "").lower() == "application/ld+json":
            self.in_json_ld = True
            self.script_data = []
        if tag == "a" and isinstance(values.get("href"), str) and len(self.links) < 100:
            self.links.append(values["href"][:512])

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "script" and self.in_json_ld:
            self.json_ld.append("".join(self.script_data)[:8000])
            self.in_json_ld = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data[:500])
        if self.in_json_ld and sum(map(len, self.script_data)) < 8000:
            self.script_data.append(data)


def _http_json(url: str, params: dict) -> dict:
    try:
        with httpx.Client(timeout=httpx.Timeout(1.5), follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url, params=params, headers={"Accept": "application/dns-json"}) as response:
                if response.is_redirect or response.status_code != 200:
                    raise EvidenceError("dns_provider_unavailable")
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_DOH_BYTES:
                        raise EvidenceError("dns_response_too_large")
        payload = json.loads(chunks)
        if not isinstance(payload, dict) or not isinstance(payload.get("Status"), int):
            raise EvidenceError("dns_invalid_response")
        return payload
    except EvidenceError:
        raise
    except httpx.TimeoutException:
        raise EvidenceError("dns_timeout") from None
    except (httpx.HTTPError, ValueError, json.JSONDecodeError):
        raise EvidenceError("dns_provider_unavailable") from None


def _dns(domain: str, query_type: str) -> tuple[list[dict], int]:
    payload = _http_json(DOH_ENDPOINT, {"name": domain, "type": query_type})
    records = []
    ttls = []
    answers = payload.get("Answer", [])
    if not isinstance(answers, list):
        raise EvidenceError("dns_invalid_response")
    for row in answers[:30]:
        if not isinstance(row, dict) or not isinstance(row.get("data"), str):
            continue
        data = row["data"][:1000]
        if query_type in {"A", "AAAA"}:
            try:
                ipaddress.ip_address(data)
            except ValueError:
                continue
        records.append({"type": query_type, "name": str(row.get("name", ""))[:253],
                        "ttl": max(0, min(int(row.get("TTL", 0)), MAX_TTL_SECONDS)), "data": data})
        ttls.append(records[-1]["ttl"])
    return records, min(ttls) if ttls else 0


def _public_ips(host: str) -> list[str]:
    records, _ = _dns(host, "A")
    ipv6, _ = _dns(host, "AAAA")
    values = [row["data"] for row in records + ipv6]
    parsed = []
    for value in values:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise EvidenceError("non_public_address")
        parsed.append(value)
    if not parsed:
        raise EvidenceError("no_public_address")
    return parsed


def _fetch_html(domain: str, initial_ips: list[str] | None = None) -> tuple[str, str, dict]:
    current = f"https://{domain}/"
    original = domain
    context = ssl.create_default_context()
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or parsed.port not in (None, 443) or not host:
            raise EvidenceError("unsafe_redirect")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise EvidenceError("unsafe_redirect")
        try:
            host = normalize_domain(host)
        except ValueError:
            raise EvidenceError("unsafe_redirect") from None
        if host != original and not host.endswith("." + original):
            raise EvidenceError("cross_domain_redirect")
        ips = initial_ips if hop == 0 and initial_ips else _public_ips(host)
        for value in ips:
            if not ipaddress.ip_address(value).is_global:
                raise EvidenceError("non_public_address")
        raw = None
        try:
            raw = socket.create_connection((ips[0], 443), timeout=1.5)
            tls = context.wrap_socket(raw, server_hostname=host)
            path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if parsed.query:
                path += "?" + quote(parsed.query[:512], safe="=&;%:@$'()*+,/?-._~")
            request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: LeakTrace-DomainVerifier/1.0\r\n"
                       "Accept: text/html,application/xhtml+xml;q=0.9\r\nAccept-Encoding: identity\r\n"
                       "Connection: close\r\n\r\n").encode("ascii")
            tls.sendall(request)
            response = HTTPResponse(tls)
            response.begin()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                response.close()
                tls.close()
                if not location or len(location) > 2048 or hop == MAX_REDIRECTS:
                    raise EvidenceError("redirect_limit")
                current = urljoin(current, location)
                continue
            if response.status != 200:
                if response.status in (401, 403, 429):
                    raise EvidenceError("website_access_denied")
                raise EvidenceError("website_unavailable")
            if "text/html" not in (response.getheader("Content-Type", "").lower()):
                raise EvidenceError("not_html")
            length = response.getheader("Content-Length")
            if length and int(length) > MAX_HTML_BYTES:
                raise EvidenceError("website_response_too_large")
            body = response.read(MAX_HTML_BYTES + 1)
            if len(body) > MAX_HTML_BYTES:
                raise EvidenceError("website_response_too_large")
            charset = response.headers.get_content_charset() or "utf-8"
            response.close()
            tls.close()
            parser = _MetadataParser()
            parser.feed(body.decode(charset, errors="replace"))
            linked_domains = set()
            for link in parser.links:
                try:
                    target = urlsplit(urljoin(current, link))
                    if target.scheme == "https" and target.hostname and target.port in (None, 443):
                        linked_domains.add(normalize_domain(target.hostname))
                except ValueError:
                    continue
            return current, " ".join(" ".join(parser.title).split())[:500], {
                "meta": parser.meta, "json_ld": parser.json_ld,
                "linked_domains": sorted(linked_domains)[:50],
                "observed_url": current,
            }
        except EvidenceError:
            if raw:
                raw.close()
            raise
        except (OSError, ssl.SSLError, UnicodeError, ValueError):
            if raw:
                raw.close()
            raise EvidenceError("website_unavailable") from None
    raise EvidenceError("redirect_limit")


def _extract_org_claims(page: dict, title: str) -> list[str]:
    candidates = [page.get("meta", {}).get("og:site_name"), page.get("meta", {}).get("application-name")]
    for value in page.get("json_ld", []):
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError):
            continue
        rows = decoded if isinstance(decoded, list) else [decoded]
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = row.get("@type")
            if isinstance(kind, list):
                kind = " ".join(str(x) for x in kind)
            if isinstance(kind, str) and any(word in kind.lower() for word in ("organization", "website", "brand")):
                name = row.get("name")
                if isinstance(name, str):
                    candidates.append(name)
    if title:
        candidates.append(title.split("|")[0].split("–")[0].split("-")[0].strip())
    out = []
    for item in candidates:
        clean = re.sub(r"\s+", " ", html.unescape(item or "")).strip()[:120]
        if clean and clean.casefold() not in {x.casefold() for x in out}:
            out.append(clean)
    return out[:10]


def _doh_evidence(domain: str) -> tuple[dict, int]:
    queries = [(domain, "A"), (domain, "AAAA"), (domain, "MX"), (domain, "TXT"),
               (f"_dmarc.{domain}", "TXT")]
    queries.extend((f"{selector}._domainkey.{domain}", "TXT") for selector in SELECTORS)
    results, ttls = [], []
    with ThreadPoolExecutor(max_workers=9, thread_name_prefix="domain-dns") as pool:
        futures = [(name, kind, pool.submit(_dns, name, kind)) for name, kind in queries]
        for name, kind, future in futures:
            try:
                rows, ttl = future.result(timeout=4)
                results.extend(rows)
                if ttl:
                    ttls.append(ttl)
            except Exception as exc:
                future.cancel()
                code = exc.code if isinstance(exc, EvidenceError) else "dns_lookup_failed"
                _log_failure("dns", domain, code)
                results.append({"type": kind, "name": name, "error": code})
    return {"records": results}, min(ttls) if ttls else CACHE_TTL_SECONDS


def collect_public_evidence(domain: str) -> tuple[dict, int]:
    domain = normalize_domain(domain)
    dns, ttl = _doh_evidence(domain)
    try:
        initial_ips = [row["data"] for row in dns["records"] if row.get("type") in {"A", "AAAA"}]
        observed_url, title, page = _fetch_html(domain, initial_ips or None)
        page["title"] = title
        page["organization_claims"] = _extract_org_claims(page, title)
        page["observed_url"] = observed_url
    except EvidenceError as exc:
        _log_failure("https", domain, exc.code)
        page = {"error": exc.code, "organization_claims": []}
    ttl = max(3600, min(ttl, CACHE_TTL_SECONDS))
    source_url = None
    if page.get("observed_url"):
        source = urlsplit(page["observed_url"])
        source_url = urlunsplit(("https", source.netloc, source.path, "", ""))
        page["observed_url"] = source_url
    dns_source = f"{DOH_ENDPOINT}?name={domain}&type=TXT"
    return {"domain": domain, "checked_at": datetime.now(timezone.utc).isoformat(),
            "dns": dns, "website": page,
            "evidence_status": "collected" if page.get("organization_claims") else
                "partial" if page.get("error") and any("data" in row for row in dns["records"]) else
                "lookup_failed" if page.get("error") else "insufficient",
            "errors": [{"stage": "dns", "category": row["error"]} for row in dns["records"] if row.get("error")][:12]
                + ([{"stage": "https", "category": page["error"]}] if page.get("error") else []),
            "source_urls": [dns_source, *([source_url] if source_url else [])]}, ttl


def cached_public_evidence(session: Session, domain: str, now: datetime | None = None,
                           correlation_id: str | None = None) -> dict:
    domain = normalize_domain(domain)
    now = now or datetime.now(timezone.utc)
    try:
        with session.begin_nested():
            row = session.get(DomainEvidenceCache, domain)
            if row and row.expires_at > now and row.evidence.get("evidence_version") == EVIDENCE_VERSION:
                return row.evidence
    except Exception as exc:
        _log_failure("cache_read", domain, "database_error", correlation_id)
        raise EvidenceError("cache_read_failed") from exc
    error_code = None
    try:
        evidence, ttl = collect_public_evidence(domain)
        if correlation_id:
            for failure in evidence.get("errors", []):
                _log_failure(failure.get("stage", "collection"), domain,
                             failure.get("category", "lookup_failed"), correlation_id)
    except (EvidenceError, ValueError) as exc:
        _log_failure("collection", domain, getattr(exc, "code", "invalid_domain"), correlation_id)
        evidence, ttl = {"domain": domain, "checked_at": now.isoformat(), "dns": {"records": []},
                         "website": {"error": getattr(exc, "code", "invalid_domain"), "organization_claims": []},
                         "source_urls": [], "evidence_status": "lookup_failed",
                         "errors": [{"stage": "collection", "category": getattr(exc, "code", "invalid_domain")}]}, 3600
        error_code = getattr(exc, "code", "invalid_domain")
    from backend.services.gemini import enrich_cached_evidence
    evidence["evidence_version"] = EVIDENCE_VERSION
    if not evidence.get("website", {}).get("organization_claims"):
        try:
            with session.begin_nested():
                evidence["gemini_interpretation"] = enrich_cached_evidence(session, evidence)
        except Exception as exc:
            code = getattr(exc, "code", "gemini_unavailable")
            _log_failure("gemini", domain, code, correlation_id)
            evidence["gemini_interpretation"] = {"status": code, "affects_classification": False}
        result = evidence["gemini_interpretation"]
        if result.get("status") not in {"grounded_lead", "api_key_not_configured"}:
            code = result.get("status", "gemini_unavailable")
            evidence.setdefault("errors", []).append({"stage": "gemini", "category": code})
            _log_failure("gemini", domain, code, correlation_id)
        if result.get("status") in {"gemini_rate_limited", "gemini_timeout", "gemini_unavailable",
                                    "gemini_invalid_response", "search_grounding_unsupported"}:
            ttl = min(ttl, 3600)
        elif result.get("status") == "insufficient_grounded_sources":
            ttl = min(ttl, 6 * 3600)
    else:
        evidence["gemini_interpretation"] = {"status": "not_needed", "affects_classification": False}
    evidence["expires_at"] = (now + timedelta(seconds=ttl)).isoformat()
    stmt = insert(DomainEvidenceCache).values(
        domain=domain, evidence=evidence, organization_claim=_first_claim(evidence),
        fetched_at=now, expires_at=now + timedelta(seconds=ttl), error_code=error_code,
    ).on_conflict_do_update(index_elements=[DomainEvidenceCache.domain], set_={
        "evidence": evidence, "organization_claim": _first_claim(evidence),
        "fetched_at": now, "expires_at": now + timedelta(seconds=ttl), "error_code": error_code,
    })
    try:
        with session.begin_nested():
            session.execute(stmt)
            session.flush()
    except Exception as exc:
        _log_failure("cache_write", domain, "database_error", correlation_id)
        raise EvidenceError("cache_write_failed") from exc
    return evidence


def _first_claim(evidence: dict) -> str | None:
    claims = evidence.get("website", {}).get("organization_claims", [])
    return claims[0] if claims else None
