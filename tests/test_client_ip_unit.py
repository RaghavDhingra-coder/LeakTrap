"""Client address for rate limits: socket peer outside mobile mode; in mobile mode
only trusted X-Forwarded-For hops counted from the right. No database needed."""

import logging
from dataclasses import replace

import pytest
from starlette.requests import Request

from backend import security
from backend.forwarding import forwarded_client
from backend.security import UNKNOWN_CLIENT, client_ip


@pytest.mark.parametrize(("chain", "hops", "expected"), [
    (["203.0.113.5"], 1, "203.0.113.5"),
    (["198.51.100.9, 203.0.113.5"], 1, "203.0.113.5"),            # forged leftmost ignored
    (["6.6.6.6, 7.7.7.7, 203.0.113.5"], 1, "203.0.113.5"),
    (["6.6.6.6, 203.0.113.5, 10.0.0.2"], 2, "203.0.113.5"),        # two proxies
    (["203.0.113.5, 10.0.0.2, 10.0.0.3"], 3, "203.0.113.5"),
    (["198.51.100.9", "203.0.113.5"], 1, "203.0.113.5"),           # several header lines, in order
    ([" 203.0.113.5 "], 1, "203.0.113.5"),
    (["2001:DB8::1"], 1, "2001:db8::1"),                           # normalised
    (["203.0.113.5"], 2, None),                                    # too few entries
    ([], 1, None),
    ([""], 1, None),                                               # empty header
    (["203.0.113.5, "], 1, None),                                  # empty rightmost entry
    (["203.0.113.5, unknown"], 1, None),                           # malformed rightmost
    (["evil, 203.0.113.5"], 2, None),                              # malformed trusted entry
    (["203.0.113.5:443"], 1, None),                                # ports are not accepted
    (["[2001:db8::1]"], 1, None),
    (["203.0.113.5, 10.0.0.2 garbage"], 2, None),                  # any malformed trusted entry refuses
    (["203.0.113.5"], 0, None),                                    # zero hops: nothing trusted
])
def test_forwarded_client(chain, hops, expected) -> None:
    assert forwarded_client(chain, hops) == expected


def request(headers: dict[str, str | list[str]] | None = None, peer: str | None = "10.0.0.9") -> Request:
    raw = []
    for name, value in (headers or {}).items():
        for v in value if isinstance(value, list) else [value]:
            raw.append((name.lower().encode(), v.encode()))
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw,
                    "client": (peer, 50000) if peer else None, "query_string": b""})


@pytest.fixture
def mode(monkeypatch):
    def set_mode(app_mode: str, hops: int | None = 0) -> None:
        monkeypatch.setattr(security, "settings", replace(security.settings, app_mode=app_mode, trusted_proxy_hops=hops))
    return set_mode


@pytest.mark.parametrize("app_mode", ["full", "ingest"])
def test_other_modes_use_the_socket_peer_and_ignore_proxy_headers(mode, app_mode) -> None:
    mode(app_mode, hops=1)  # even if a hop count were configured
    forged = {"X-Forwarded-For": "203.0.113.5", "X-Real-IP": "203.0.113.6", "Forwarded": "for=203.0.113.7"}
    assert client_ip(request(forged)) == "10.0.0.9"
    assert client_ip(request(peer=None)) == "unknown"


def test_mobile_mode_with_zero_hops_shares_the_unknown_key(mode) -> None:
    mode("mobile", hops=0)
    assert client_ip(request({"X-Forwarded-For": "203.0.113.5"})) == UNKNOWN_CLIENT
    assert client_ip(request()) == UNKNOWN_CLIENT  # the socket peer is the proxy, not the client


@pytest.mark.parametrize(("hops", "headers", "expected"), [
    (1, {"X-Forwarded-For": "203.0.113.5"}, "203.0.113.5"),
    (1, {"X-Forwarded-For": "1.1.1.1, 203.0.113.5"}, "203.0.113.5"),
    (1, {"X-Forwarded-For": ["1.1.1.1", "203.0.113.5"]}, "203.0.113.5"),
    (2, {"X-Forwarded-For": "1.1.1.1, 203.0.113.5, 10.0.0.2"}, "203.0.113.5"),
    (2, {"X-Forwarded-For": "203.0.113.5"}, UNKNOWN_CLIENT),
    (1, {"X-Forwarded-For": "203.0.113.5, not-an-ip"}, UNKNOWN_CLIENT),
    (1, {"X-Forwarded-For": ""}, UNKNOWN_CLIENT),
    (1, {}, UNKNOWN_CLIENT),
    # Other client-controlled headers are never a fallback.
    (1, {"X-Real-IP": "203.0.113.5", "Forwarded": "for=203.0.113.5", "CF-Connecting-IP": "203.0.113.5",
         "True-Client-IP": "203.0.113.5"}, UNKNOWN_CLIENT),
])
def test_mobile_mode_trusts_only_hops_from_the_right(mode, hops, headers, expected) -> None:
    mode("mobile", hops=hops)
    assert client_ip(request(headers)) == expected


def test_forging_the_leftmost_address_never_changes_the_key(mode) -> None:
    mode("mobile", hops=1)
    keys = {client_ip(request({"X-Forwarded-For": f"{i}.{i}.{i}.{i}, 203.0.113.5"})) for i in range(1, 50)}
    assert keys == {"203.0.113.5"}


def test_unknown_client_is_logged_without_request_data(mode, caplog, monkeypatch) -> None:
    mode("mobile", hops=1)
    monkeypatch.setattr(security, "_unknown_client_requests", 0)
    caplog.set_level(logging.DEBUG, logger="leaktrace.security")
    for _ in range(150):
        client_ip(request({"X-Forwarded-For": "198.51.100.77, garbage", "X-Real-IP": "198.51.100.78"}))
    messages = [r.getMessage() for r in caplog.records if r.name == "leaktrace.security"]
    assert len(messages) == 2  # the first, then every 100th
    assert messages[0] == "Client address unknown for 1 request(s); using the shared rate-limit key"
    assert not any(value in caplog.text for value in ("198.51.100", "garbage", "10.0.0.9"))
