"""Application configuration loaded from environment variables.

A local .env file is loaded if present but is not required: every setting
has a safe default, except DATABASE_URL, which is only needed by code that
talks to the database.
"""

import os
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dotenv import load_dotenv
from sqlalchemy.engine import make_url

# Load a local .env file if present. Real environment variables take precedence.
load_dotenv()

APP_NAME = "LeakTrace"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = (
    "Privacy-focused data-leak investigation platform. LeakTrace helps users "
    "identify likely sources of personal-data leaks by assigning distinct "
    "identity variants to different websites."
)


APP_MODES = ("full", "ingest", "mobile")
MIN_SECRET_LENGTH = 32
MAX_TRUSTED_PROXY_HOPS = 3


@dataclass(frozen=True)
class Settings:
    environment: str
    # "full": every API and the local dashboard. "ingest": only the health
    # checks and POST /ingest/email, for a publicly reachable deployment.
    # "mobile": only the health checks and the /mobile/v1 API, for a separate
    # publicly reachable deployment that never holds the ingest secret.
    app_mode: str
    log_level: str
    # Expected format: postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE
    database_url: str | None = field(repr=False)
    db_pool_size: int
    db_max_overflow: int
    db_pool_recycle_seconds: int
    # Domain for generated signup aliases (e.g. aliases.example.com). Generating
    # an alias does not configure mail routing or verify delivery.
    alias_domain: str | None
    alias_prefix: str
    alias_suffix_length: int
    marker_max_retries: int
    # Shared secret the email Worker sends as a Bearer token. Ingestion is
    # disabled while it is unset.
    ingest_secret: str | None = field(repr=False)
    ingest_max_bytes: int
    # Dashboard routes require an authenticated session. Access is loopback-only
    # unless the explicit HTTPS public-origin mode is configured.
    dashboard_enabled: bool
    # Accounts and sessions.
    session_idle_hours: int
    session_max_days: int
    extension_token_hours: int
    # Paired mobile devices: absolute lifetime, and how long a token may go unused.
    mobile_token_days: int
    mobile_idle_days: int
    # Secure cookies need HTTPS; off by default only in development (http://127.0.0.1).
    cookie_secure: bool
    # Unverified accounts may sign in only where this is on (default: development).
    allow_unverified_login: bool
    # Key for hashing rate-limit identifiers (IPs, emails). Required outside
    # development; a random per-process key is used when unset.
    secret_key: str | None = field(repr=False)
    # Name of a configured email delivery provider. None: no emails are sent.
    email_delivery: str | None
    # Mobile mode only: how many proxies in front of the app append to
    # X-Forwarded-For (counted from the right). 0: the client address is unknown
    # and pairing rate limits share one key. None: the value was not 0-3.
    trusted_proxy_hops: int | None = 0
    # Mobile mode, outside production only: log forwarding headers of marked
    # /health requests, to establish trusted_proxy_hops on a staging deployment.
    proxy_diagnostics: bool = False
    dashboard_public: bool = False
    dashboard_public_origin: str | None = None
    forwarded_allow_ips: str = "127.0.0.1,::1"
    forwarded_allow_ips_explicit: bool = False


def _flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _proxy_hops() -> int | None:
    raw = os.getenv("LEAKTRACE_TRUSTED_PROXY_HOPS", "0").strip() or "0"
    if not raw.isdigit() or int(raw) > MAX_TRUSTED_PROXY_HOPS:
        return None
    return int(raw)


def normalize_database_url(value: str | None) -> str | None:
    """Use psycopg 3 for standard PostgreSQL URLs accepted from hosting providers.

    SQLAlchemy defaults ``postgresql://`` to a different driver. Normalize only
    the standard PostgreSQL schemes; leave malformed and other-driver URLs
    untouched so configuration validation rejects them without guessing.
    """
    if not value:
        return value
    try:
        url = make_url(value)
    except Exception:
        return value
    if url.drivername == "postgresql":
        return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)
    return value


def parse_forwarded_allow_ips(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None:
    """Parse Uvicorn's proxy allowlist; hostnames and wildcard trust are refused."""
    entries = [entry.strip() for entry in value.split(",")]
    if not entries or any(not entry or entry == "*" for entry in entries):
        return None
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=True))
        except ValueError:
            return None
    if any(network.prefixlen == 0 for network in networks):
        return None
    return tuple(networks)


def valid_public_dashboard_origin(value: str | None) -> str | None:
    """Return a canonical HTTPS origin, rejecting paths, credentials and fragments."""
    if not value or value != value.strip():
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        return None
    if (parsed.scheme.lower() != "https" or not host or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or "?" in value or "#" in value or "\\" in parsed.netloc):
        return None
    try:
        normalized_host = ipaddress.ip_address(host).compressed
        if ":" in normalized_host:
            normalized_host = f"[{normalized_host}]"
    except ValueError:
        try:
            normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not normalized_host or any(
            not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label)
            for label in normalized_host.split(".")
        ):
            return None
    suffix = f":{port}" if port is not None and port != 443 else ""
    return f"https://{normalized_host}{suffix}"


def public_dashboard_proxy_allowlist_valid(value: str, explicit: bool) -> bool:
    networks = parse_forwarded_allow_ips(value)
    if not explicit or networks is None:
        return False
    loopbacks = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
    return any(
        not any(network.version == loopback.version and network.subnet_of(loopback) for loopback in loopbacks)
        for network in networks
    )


def get_settings() -> Settings:
    """Read settings from the environment, falling back to defaults."""
    environment = os.getenv("LEAKTRACE_ENV", "development")
    return Settings(
        environment=environment,
        app_mode=os.getenv("LEAKTRACE_APP_MODE", "full").strip().lower() or "full",
        log_level=os.getenv("LEAKTRACE_LOG_LEVEL", "INFO").upper(),
        database_url=normalize_database_url(os.getenv("DATABASE_URL") or None),
        db_pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
        db_max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
        db_pool_recycle_seconds=int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
        alias_domain=os.getenv("LEAKTRACE_ALIAS_DOMAIN") or None,
        alias_prefix=os.getenv("LEAKTRACE_ALIAS_PREFIX", ""),
        alias_suffix_length=int(os.getenv("LEAKTRACE_ALIAS_SUFFIX_LENGTH", "8")),
        marker_max_retries=int(os.getenv("LEAKTRACE_MARKER_MAX_RETRIES", "5")),
        ingest_secret=os.getenv("LEAKTRACE_INGEST_SECRET") or None,
        ingest_max_bytes=int(os.getenv("LEAKTRACE_INGEST_MAX_BYTES", "16384")),
        dashboard_enabled=_flag("LEAKTRACE_DASHBOARD_ENABLED", environment == "development"),
        session_idle_hours=int(os.getenv("LEAKTRACE_SESSION_IDLE_HOURS", "12")),
        session_max_days=int(os.getenv("LEAKTRACE_SESSION_MAX_DAYS", "7")),
        extension_token_hours=int(os.getenv("LEAKTRACE_EXTENSION_TOKEN_HOURS", "8")),
        mobile_token_days=int(os.getenv("LEAKTRACE_MOBILE_TOKEN_DAYS", "30")),
        mobile_idle_days=int(os.getenv("LEAKTRACE_MOBILE_IDLE_DAYS", "14")),
        cookie_secure=_flag("LEAKTRACE_COOKIE_SECURE", environment != "development"),
        allow_unverified_login=_flag("LEAKTRACE_ALLOW_UNVERIFIED_LOGIN", environment == "development"),
        secret_key=os.getenv("LEAKTRACE_SECRET_KEY") or None,
        email_delivery=os.getenv("LEAKTRACE_EMAIL_DELIVERY") or None,
        trusted_proxy_hops=_proxy_hops(),
        proxy_diagnostics=_flag("LEAKTRACE_PROXY_DIAGNOSTICS", False),
        dashboard_public=_flag("LEAKTRACE_DASHBOARD_PUBLIC", False),
        dashboard_public_origin=os.getenv("LEAKTRACE_DASHBOARD_PUBLIC_ORIGIN") or None,
        forwarded_allow_ips=os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1,::1"),
        forwarded_allow_ips_explicit="FORWARDED_ALLOW_IPS" in os.environ,
    )


def configuration_problems(s: Settings) -> list[str]:
    """Settings that make this deployment unusable. Names variables, never values."""
    problems = []
    if s.app_mode not in APP_MODES:
        problems.append("LEAKTRACE_APP_MODE must be 'full', 'ingest' or 'mobile'")
    if not s.database_url:
        problems.append("DATABASE_URL is not set")
    elif not s.database_url.startswith("postgresql+psycopg://"):
        problems.append("DATABASE_URL must start with postgresql+psycopg://")
    if s.app_mode == "ingest":
        if not s.ingest_secret or len(s.ingest_secret) < MIN_SECRET_LENGTH:
            problems.append(f"LEAKTRACE_INGEST_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        if not s.alias_domain:
            problems.append("LEAKTRACE_ALIAS_DOMAIN is not set")
    elif s.app_mode == "mobile":
        # The mobile service is public and holds user data: it must never hold
        # the email Worker's secret, serve the dashboard, or run without a key.
        if s.ingest_secret:
            problems.append("LEAKTRACE_INGEST_SECRET must not be set in mobile mode")
        if s.dashboard_enabled:
            problems.append("LEAKTRACE_DASHBOARD_ENABLED must be false in mobile mode")
        if not s.secret_key or len(s.secret_key) < MIN_SECRET_LENGTH:
            problems.append(f"LEAKTRACE_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters in mobile mode")
        if not s.alias_domain:
            problems.append("LEAKTRACE_ALIAS_DOMAIN is not set")
        if s.trusted_proxy_hops is None:
            problems.append(f"LEAKTRACE_TRUSTED_PROXY_HOPS must be an integer from 0 to {MAX_TRUSTED_PROXY_HOPS}")
        if s.proxy_diagnostics and s.environment == "production":
            problems.append("LEAKTRACE_PROXY_DIAGNOSTICS must not be enabled in production")
    elif s.environment != "development" and not s.secret_key:
        problems.append("LEAKTRACE_SECRET_KEY is not set")
    if s.dashboard_public:
        if s.app_mode != "full":
            problems.append("LEAKTRACE_DASHBOARD_PUBLIC requires LEAKTRACE_APP_MODE=full")
        if not s.dashboard_enabled:
            problems.append("LEAKTRACE_DASHBOARD_PUBLIC requires LEAKTRACE_DASHBOARD_ENABLED=true")
        if valid_public_dashboard_origin(s.dashboard_public_origin) is None:
            problems.append("LEAKTRACE_DASHBOARD_PUBLIC_ORIGIN must be a valid HTTPS origin")
        if not public_dashboard_proxy_allowlist_valid(s.forwarded_allow_ips, s.forwarded_allow_ips_explicit):
            problems.append("FORWARDED_ALLOW_IPS must be an explicit, non-loopback IP/CIDR allowlist for public dashboard access")
    if parse_forwarded_allow_ips(s.forwarded_allow_ips) is None:
        problems.append("FORWARDED_ALLOW_IPS must contain only explicit IP addresses or CIDRs; wildcards are not allowed")
    return problems


def mask_database_url(url: str | None) -> str:
    """Return a database URL that is safe to log (password hidden)."""
    if not url:
        return "<not configured>"
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<invalid DATABASE_URL>"


settings = get_settings()
