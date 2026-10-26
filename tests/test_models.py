"""Model and metadata tests. These do not need a PostgreSQL server."""

import pytest
from sqlalchemy import DateTime
from sqlalchemy.dialects.postgresql import JSONB

import backend.models as models
from backend.database import Base

TABLES = {
    "users",
    "signups",
    "consent_receipts",
    "mail_log",
    "incidents",
    "complaint_drafts",
    "reports",
    "leak_edges",
}

REQUIRED_COLUMNS = {
    "users": {"id", "created_at"},
    "signups": {
        "id", "user_id", "site_name", "site_domain", "alias", "nickname",
        "surname_variant", "real_name_required", "real_name_used",
        "created_at", "updated_at",
    },
    "consent_receipts": {
        "id", "user_id", "signup_id", "source_url", "privacy_notice_text",
        "consent_text", "captured_at", "content_hash", "created_at",
    },
    "mail_log": {
        "id", "user_id", "signup_id", "alias", "sender", "subject", "is_spam",
        "received_at", "created_at",
    },
    "incidents": {
        "id", "user_id", "channel", "message_text", "result", "matched_site",
        "confidence", "evidence", "created_at",
    },
    "complaint_drafts": {
        "id", "user_id", "incident_id", "consent_receipt_id", "draft_text",
        "status", "created_at", "updated_at",
    },
    "reports": {
        "id", "user_id", "site_name", "description", "evidence", "status",
        "created_at", "updated_at",
    },
    "leak_edges": {
        "id", "user_id", "source_type", "source_id", "target_type", "target_id",
        "relationship_type", "evidence", "confidence", "created_at",
    },
}

# (table, column) -> (referenced "table.column", ON DELETE rule)
FOREIGN_KEYS = {
    ("signups", "user_id"): ("users.id", "RESTRICT"),
    ("consent_receipts", "user_id"): ("users.id", "RESTRICT"),
    ("consent_receipts", "signup_id"): ("signups.id", "SET NULL"),
    ("mail_log", "user_id"): ("users.id", "RESTRICT"),
    ("mail_log", "signup_id"): ("signups.id", "SET NULL"),
    ("incidents", "user_id"): ("users.id", "RESTRICT"),
    ("complaint_drafts", "user_id"): ("users.id", "RESTRICT"),
    ("complaint_drafts", "incident_id"): ("incidents.id", "SET NULL"),
    ("complaint_drafts", "consent_receipt_id"): ("consent_receipts.id", "SET NULL"),
    ("reports", "user_id"): ("users.id", "RESTRICT"),
    ("leak_edges", "user_id"): ("users.id", "RESTRICT"),
}

NOT_NULL_COLUMNS = {
    ("signups", "site_name"),
    ("signups", "real_name_required"),
    ("signups", "real_name_used"),
    ("consent_receipts", "privacy_notice_text"),
    ("consent_receipts", "captured_at"),
    ("mail_log", "is_spam"),
    ("mail_log", "received_at"),
    ("incidents", "channel"),
    ("complaint_drafts", "draft_text"),
    ("complaint_drafts", "status"),
    ("reports", "site_name"),
    ("reports", "status"),
    ("leak_edges", "source_type"),
    ("leak_edges", "source_id"),
    ("leak_edges", "target_type"),
    ("leak_edges", "target_id"),
    ("leak_edges", "relationship_type"),
}


def table(name: str):
    return Base.metadata.tables[name]


def index(table_name: str, index_name: str):
    return next(i for i in table(table_name).indexes if i.name == index_name)


# Account tables added in migration 0004.
ACCOUNT_TABLES = {"user_sessions", "extension_pairings", "email_verification_tokens", "auth_events", "ownership_claims"}
# Credentials die with their user; nothing else may cascade.
CASCADE_ALLOWED = {("user_sessions", "user_id"), ("extension_pairings", "user_id"), ("email_verification_tokens", "user_id")}


def test_all_models_exported() -> None:
    assert len(models.__all__) == 13
    for name in models.__all__:
        assert getattr(models, name).__tablename__ in TABLES | ACCOUNT_TABLES


def test_all_tables_registered_in_metadata() -> None:
    assert TABLES <= set(Base.metadata.tables)


@pytest.mark.parametrize("table_name", sorted(TABLES))
def test_required_columns_and_primary_key(table_name: str) -> None:
    t = table(table_name)
    assert REQUIRED_COLUMNS[table_name] <= set(t.columns.keys())
    assert [c.name for c in t.primary_key.columns] == ["id"]


@pytest.mark.parametrize(("table_name", "column"), sorted(FOREIGN_KEYS))
def test_foreign_keys(table_name: str, column: str) -> None:
    target, ondelete = FOREIGN_KEYS[(table_name, column)]
    fks = list(table(table_name).columns[column].foreign_keys)
    assert len(fks) == 1
    assert fks[0].target_fullname == target
    assert fks[0].ondelete == ondelete
    assert table(table_name).columns[column].nullable


def test_no_cascading_deletes() -> None:
    for t in Base.metadata.tables.values():
        for fk in t.foreign_keys:
            if (t.name, fk.parent.name) in CASCADE_ALLOWED:
                continue
            assert fk.ondelete != "CASCADE", f"{t.name}.{fk.parent.name} cascades"


def test_only_credential_tables_cascade_with_their_user() -> None:
    cascading = {(t.name, fk.parent.name) for t in Base.metadata.tables.values()
                 for fk in t.foreign_keys if fk.ondelete == "CASCADE"}
    assert cascading == CASCADE_ALLOWED
    # The ownership audit trail can never disappear silently with a user.
    [fk] = Base.metadata.tables["ownership_claims"].columns["user_id"].foreign_keys
    assert fk.ondelete == "RESTRICT"


def test_account_columns_and_secret_storage() -> None:
    users = table("users")
    assert {"email", "password_hash", "email_verified_at", "updated_at", "disabled_at"} <= set(users.columns.keys())
    assert "ck_users_credentials_complete" in {c.name for c in users.constraints}
    assert index("users", "uq_users_email_lower").unique
    # Only hashes of tokens and codes are stored.
    assert "token_hash" in table("user_sessions").columns and "token" not in table("user_sessions").columns
    assert {"code_hash", "secret_hash"} <= set(table("extension_pairings").columns.keys())
    assert "token_hash" in table("email_verification_tokens").columns
    assert set(table("auth_events").columns.keys()) == {"id", "kind", "key_hash", "created_at"}


def test_leak_edge_endpoints_are_not_foreign_keys() -> None:
    t = table("leak_edges")
    for column in ("source_id", "target_id"):
        assert not t.columns[column].foreign_keys


@pytest.mark.parametrize(("table_name", "column"), sorted(NOT_NULL_COLUMNS))
def test_required_columns_are_not_nullable(table_name: str, column: str) -> None:
    assert table(table_name).columns[column].nullable is False


def test_timestamp_columns_are_timezone_aware() -> None:
    for t in Base.metadata.tables.values():
        for c in t.columns:
            if c.name.endswith("_at"):
                assert isinstance(c.type, DateTime) and c.type.timezone, f"{t.name}.{c.name}"


@pytest.mark.parametrize("table_name", ["incidents", "reports", "leak_edges"])
def test_evidence_columns_use_jsonb(table_name: str) -> None:
    assert isinstance(table(table_name).columns["evidence"].type, JSONB)


def test_defaults() -> None:
    assert table("reports").columns["status"].server_default.arg == "pending_review"
    assert table("complaint_drafts").columns["status"].server_default.arg == "draft"


def test_signup_alias_unique_case_insensitive() -> None:
    ix = index("signups", "uq_signups_alias_lower")
    assert ix.unique
    assert "lower(signups.alias)" == str(ix.expressions[0])
    assert str(ix.dialect_options["postgresql"]["where"]) == "signups.alias IS NOT NULL"


def test_signup_nickname_unique_per_owner() -> None:
    ix = index("signups", "uq_signups_user_id_nickname_lower")
    assert ix.unique
    assert ix.dialect_options["postgresql"]["nulls_not_distinct"] is True
    assert str(ix.expressions[0]) == "signups.user_id"
    assert "lower(signups.nickname)" == str(ix.expressions[1])


def test_lookup_indexes_exist() -> None:
    expected = {
        "signups": {"ix_signups_nickname_lower", "ix_signups_site_domain", "ix_signups_user_id"},
        "mail_log": {
            "ix_mail_log_received_at",
            "ix_mail_log_signup_id_received_at",
            "ix_mail_log_user_id_received_at",
            "ix_mail_log_alias_lower",
        },
        "incidents": {"ix_incidents_user_id_created_at", "ix_incidents_channel"},
        "leak_edges": {"ix_leak_edges_source", "ix_leak_edges_target", "ix_leak_edges_user_id"},
    }
    for table_name, names in expected.items():
        assert names <= {i.name for i in table(table_name).indexes}


def test_incident_channel_check_constraint() -> None:
    names = {c.name for c in table("incidents").constraints}
    assert "ck_incidents_channel_allowed" in names
