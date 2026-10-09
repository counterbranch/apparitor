"""Local-only reference service for collecting and investigating audit evidence."""

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from apparitor.audit import AuditEvidence, EventKind, summarize_evidence

MAX_EVENT_BYTES = 32_768
MAX_BATCH_EVENTS = 100
MAX_PAGE_SIZE = 100
MAX_SUMMARY_EVENTS = 1_000
MAX_TEXT = 256
MAX_REFS = 64
SQLITE_BUSY_TIMEOUT_MS = 10_000


class Credential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_ref: str = Field(min_length=1, max_length=MAX_TEXT)
    role: Literal["writer", "reader"]


class Event(BaseModel):
    """Strict wire schema matching the bounded AuditEvidence JSON representation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(min_length=1, max_length=MAX_TEXT)
    event_kind: EventKind
    evidence_id: str = Field(min_length=1, max_length=MAX_TEXT)
    event_id: str = Field(min_length=1, max_length=MAX_TEXT)
    observed_at: datetime
    tenant_ref: str = Field(min_length=1, max_length=MAX_TEXT)
    principal_refs: list[str] = Field(max_length=MAX_REFS)
    request_refs: list[str] = Field(max_length=MAX_REFS)
    request_count: int = Field(ge=0, le=1_000_000)
    policy_id: str | None = Field(default=None, max_length=MAX_TEXT)
    policy_version: str | None = Field(default=None, max_length=MAX_TEXT)
    correlation_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    verdict: str | None = Field(default=None, max_length=MAX_TEXT)
    evaluation_status: str = Field(min_length=1, max_length=MAX_TEXT)
    latency_ms: float | None = Field(default=None, ge=0)
    cache_status: Literal["not_applicable", "unknown", "hit", "miss"]
    oversight_status: Literal["not_required", "not_observed", "pending", "approved", "rejected"]
    error_code: str | None = Field(default=None, max_length=MAX_TEXT)
    execution_status: Literal["not_observed", "not_started", "succeeded", "failed", "cancelled"]
    execution_observed_at: datetime | None = None
    execution_outcome_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    not_collected: list[str] = Field(max_length=MAX_REFS)
    trace_id: str | None = Field(default=None, max_length=MAX_TEXT)
    run_id: str | None = Field(default=None, max_length=MAX_TEXT)
    span_id: str | None = Field(default=None, max_length=MAX_TEXT)
    parent_span_id: str | None = Field(default=None, max_length=MAX_TEXT)
    call_id: str | None = Field(default=None, max_length=MAX_TEXT)
    user_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    agent_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    workload_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    device_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    session_ref: str | None = Field(default=None, max_length=MAX_TEXT)
    integration: str | None = Field(default=None, max_length=MAX_TEXT)
    action_refs: list[str] = Field(default_factory=list, max_length=MAX_REFS)
    resource_refs: list[str] = Field(default_factory=list, max_length=MAX_REFS)
    argument_fingerprints: list[str] = Field(default_factory=list, max_length=MAX_REFS)
    reason_code: str | None = Field(default=None, max_length=MAX_TEXT)
    coverage_status: Literal["instrumented", "unknown"] | None = None

    @field_validator("observed_at", "execution_observed_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamp must include a timezone")
        return value

    @field_validator(
        "principal_refs",
        "request_refs",
        "not_collected",
        "action_refs",
        "resource_refs",
        "argument_fingerprints",
    )
    @classmethod
    def bounded_refs(cls, value: list[str]) -> list[str]:
        if any(not ref or len(ref) > MAX_TEXT or not ref.isprintable() for ref in value):
            raise ValueError("references must be printable and bounded")
        return value

    @model_validator(mode="after")
    def paired_policy(self) -> "Event":
        if (self.policy_id is None) != (self.policy_version is None):
            raise ValueError("policy_id and policy_version must be supplied together")
        return self


class IngestBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[Event] = Field(min_length=1, max_length=MAX_BATCH_EVENTS)


class Principal(BaseModel):
    token: str
    tenant_ref: str
    role: Literal["writer", "reader"]


def _credentials_from_env() -> dict[str, Credential]:
    raw = os.environ.get("APPARITOR_OBSERVE_CREDENTIALS")
    if not raw:
        raise RuntimeError("APPARITOR_OBSERVE_CREDENTIALS is required")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError("APPARITOR_OBSERVE_CREDENTIALS must be a non-empty object")
    return {token: Credential.model_validate(value) for token, value in parsed.items()}


def _protect_database_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{path}{suffix}")
        try:
            before = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("database and sidecars must be owned, regular files")
        if before.st_uid != os.getuid():
            raise ValueError("database and sidecars must be owned, regular files")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            after = os.fstat(descriptor)
            if (
                not stat.S_ISREG(after.st_mode)
                or after.st_uid != os.getuid()
                or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError("database file changed while securing it")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)


def _prepare_database(path: Path) -> None:
    parent = path.parent
    parent_stat = parent.lstat()
    if (
        parent.is_symlink()
        or not parent.is_dir()
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o022
    ):
        raise ValueError("database parent must be an owned, private directory")
    _protect_database_files(path)
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        _protect_database_files(path)
    else:
        os.close(descriptor)


def _decode_event(value: str) -> dict[str, Any]:
    return json.loads(value)


def create_app(
    *, database_path: str | Path | None = None, credentials: dict[str, Credential] | None = None
) -> FastAPI:
    db_path = Path(database_path or os.environ.get("APPARITOR_OBSERVE_DB", "observe.sqlite3"))
    credential_map = credentials if credentials is not None else _credentials_from_env()
    if not credential_map or any(len(token) < 32 for token in credential_map):
        raise ValueError("credentials require random tokens of at least 32 characters")

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        _prepare_database(db_path)
        connection = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                tenant_ref TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                trace_id TEXT,
                event_json TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                PRIMARY KEY (tenant_ref, evidence_id)
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS events_tenant_time ON events(tenant_ref, observed_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS events_tenant_trace ON events(tenant_ref, trace_id)"
        )
        _protect_database_files(db_path)
        application.state.db = connection
        application.state.db_lock = threading.RLock()
        try:
            yield
        finally:
            connection.close()

    app = FastAPI(title="Apparitor Observe local reference", lifespan=lifespan)

    def authenticate(authorization: Annotated[str | None, Header()] = None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="bearer credential required")
        supplied = authorization[7:]
        matched_token: str | None = None
        matched_credential: Credential | None = None
        for token, credential in credential_map.items():
            if hmac.compare_digest(supplied, token):
                matched_token, matched_credential = token, credential
        if matched_token is None or matched_credential is None:
            raise HTTPException(status_code=401, detail="invalid credential")
        return Principal(token=matched_token, **matched_credential.model_dump())

    def authenticate_writer(
        principal: Annotated[Principal, Depends(authenticate)],
    ) -> Principal:
        if principal.role != "writer":
            raise HTTPException(status_code=403, detail="writer credential required")
        return principal

    def authenticate_reader(
        principal: Annotated[Principal, Depends(authenticate)],
    ) -> Principal:
        if principal.role != "reader":
            raise HTTPException(status_code=403, detail="reader credential required")
        return principal

    @app.post("/v1/events:ingest")
    async def ingest(
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_writer)],
    ) -> dict[str, list[str]]:
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_EVENT_BYTES * MAX_BATCH_EVENTS:
                raise HTTPException(status_code=413, detail="batch is too large")
            body.extend(chunk)
        try:
            raw = json.loads(body)
            batch = IngestBatch.model_validate(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="invalid event batch") from exc
        canonical: list[tuple[Event, str, str]] = []
        for event in batch.events:
            if event.tenant_ref != principal.tenant_ref:
                raise HTTPException(
                    status_code=403, detail="event tenant does not match credential"
                )
            encoded = event.model_dump_json(exclude_none=False)
            if len(encoded.encode()) > MAX_EVENT_BYTES:
                raise HTTPException(status_code=413, detail="event is too large")
            try:
                AuditEvidence.from_dict(json.loads(encoded))
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="invalid audit evidence") from exc
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            canonical.append((event, encoded, digest))
        db: sqlite3.Connection = request.app.state.db
        try:
            with request.app.state.db_lock, db:
                for event, encoded, digest in canonical:
                    existing = db.execute(
                        "SELECT event_hash FROM events WHERE tenant_ref=? AND evidence_id=?",
                        (principal.tenant_ref, event.evidence_id),
                    ).fetchone()
                    if existing is not None and existing["event_hash"] != digest:
                        raise HTTPException(status_code=409, detail="conflicting evidence_id")
                    db.execute(
                        "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            principal.tenant_ref,
                            event.evidence_id,
                            event.observed_at.astimezone(timezone.utc).isoformat(),
                            event.trace_id,
                            encoded,
                            digest,
                        ),
                    )
                _protect_database_files(db_path)
        except sqlite3.DatabaseError as exc:
            raise HTTPException(status_code=503, detail="durable ingest failed") from exc
        return {"acknowledged_ids": [event.evidence_id for event, _, _ in canonical]}

    def load_events(
        request: Request,
        principal: Principal,
        *,
        trace_id: str | None = None,
        limit: int = MAX_SUMMARY_EVENTS,
        offset: int = 0,
        newest_first: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        sql = "SELECT event_json FROM events WHERE tenant_ref=?"
        params: list[str] = [principal.tenant_ref]
        if trace_id is not None:
            sql += " AND trace_id=?"
            params.append(trace_id)
        count_sql = sql.replace("SELECT event_json", "SELECT COUNT(*)")
        with request.app.state.db_lock:
            total = request.app.state.db.execute(count_sql, params).fetchone()[0]
            direction = "DESC" if newest_first else "ASC"
            sql += f" ORDER BY observed_at {direction}, evidence_id {direction} LIMIT ? OFFSET ?"
            rows = request.app.state.db.execute(sql, [*params, limit, offset]).fetchall()
        return [_decode_event(row["event_json"]) for row in rows], total

    @app.get("/v1/events")
    async def query_events(
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_reader)],
        tenant_ref: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        policy: str | None = None,
        outcome: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
        offset: int = Query(0, ge=0, le=100_000),
    ) -> dict[str, Any]:
        if tenant_ref is not None and tenant_ref != principal.tenant_ref:
            raise HTTPException(status_code=403, detail="query tenant does not match credential")
        if (start is not None and start.tzinfo is None) or (end is not None and end.tzinfo is None):
            raise HTTPException(status_code=422, detail="time filters require a timezone")
        clauses = ["tenant_ref=?"]
        params: list[Any] = [principal.tenant_ref]
        filters = {
            "policy": (policy, "json_extract(event_json, '$.policy_id')=?"),
            "start": (start, "observed_at>=?"),
            "end": (end, "observed_at<=?"),
        }
        for value, clause in filters.values():
            if value is not None:
                clauses.append(clause)
                params.append(
                    value.astimezone(timezone.utc).isoformat()
                    if isinstance(value, datetime)
                    else value
                )
        for value, path in ((action, "action_refs"), (resource, "resource_refs")):
            if value is not None:
                clauses.append(
                    f"EXISTS (SELECT 1 FROM json_each(event_json, '$.{path}') WHERE value=?)"
                )
                params.append(value)
        if actor is not None:
            clauses.append(
                "(EXISTS (SELECT 1 FROM json_each(event_json, '$.principal_refs') "
                "WHERE value=?) OR json_extract(event_json, '$.user_ref')=? OR "
                "json_extract(event_json, '$.agent_ref')=? OR "
                "json_extract(event_json, '$.workload_ref')=?)"
            )
            params.extend([actor] * 4)
        if outcome is not None:
            clauses.append(
                "? IN (json_extract(event_json, '$.verdict'), "
                "json_extract(event_json, '$.evaluation_status'), "
                "json_extract(event_json, '$.execution_status'))"
            )
            params.append(outcome)
        where = " AND ".join(clauses)
        db: sqlite3.Connection = request.app.state.db
        with request.app.state.db_lock:
            total = db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
            rows = db.execute(
                f"SELECT event_json FROM events WHERE {where} "
                "ORDER BY observed_at, evidence_id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return {
            "items": [_decode_event(row["event_json"]) for row in rows],
            "total": total,
            "offset": offset,
        }

    @app.get("/v1/traces/{trace_id}")
    async def trace_timeline(
        trace_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_reader)],
        limit: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
        offset: int = Query(0, ge=0, le=100_000),
    ) -> dict[str, Any]:
        items, total = load_events(
            request, principal, trace_id=trace_id, limit=limit, offset=offset
        )
        return {"trace_id": trace_id, "items": items, "total": total, "offset": offset}

    @app.get("/v1/events/{evidence_id}")
    async def event_detail(
        evidence_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_reader)],
    ) -> dict[str, Any]:
        with request.app.state.db_lock:
            row = request.app.state.db.execute(
                "SELECT event_json FROM events WHERE tenant_ref=? AND evidence_id=?",
                (principal.tenant_ref, evidence_id),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="event not found")
        return _decode_event(row["event_json"])

    def alert_reason(event: dict[str, Any]) -> str | None:
        if event.get("event_kind") == "boundary_refusal":
            return "boundary_refused"
        if event.get("event_kind") == "mapping_failure":
            return "mapping_failure"
        if event.get("event_kind") == "cancelled":
            return "authorization_cancelled"
        is_decision = str(event.get("event_kind", "")).endswith("decision")
        if (
            is_decision
            and event.get("verdict") == "block"
            and event.get("evaluation_status") == "success"
        ):
            return "policy_block"
        if is_decision and (event.get("evaluation_status") == "error" or event.get("error_code")):
            return "evaluation_fault"
        if event.get("event_kind") == "collection_gap" or event.get("coverage_status") == "unknown":
            return "collection_gap"
        return None

    @app.get("/v1/alerts")
    async def alerts(
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_reader)],
    ) -> dict[str, Any]:
        events, total = load_events(request, principal, limit=MAX_SUMMARY_EVENTS, newest_first=True)
        items = []
        for event in events:
            reason = alert_reason(event)
            if reason:
                items.append(
                    {
                        "evidence_id": event["evidence_id"],
                        "observed_at": event["observed_at"],
                        "reason": reason,
                    }
                )
        return {
            "items": items,
            "classification": "operational_signal_not_statutory_incident",
            "sample": {
                "rows_scanned": len(events),
                "tenant_event_total": total,
                "truncated": total > len(events),
            },
        }

    @app.get("/v1/summary")
    async def summary(
        request: Request,
        principal: Annotated[Principal, Depends(authenticate_reader)],
    ) -> dict[str, Any]:
        events, total = load_events(request, principal, limit=MAX_SUMMARY_EVENTS, newest_first=True)
        records = [AuditEvidence.from_dict(event) for event in events]
        evidence_summary = summarize_evidence(records)
        denominators = evidence_summary["denominators"]
        outcomes = evidence_summary["decision_outcomes"]
        faults = evidence_summary["authorization_faults"]
        oversight = evidence_summary["oversight"]
        assert isinstance(denominators, dict)
        assert isinstance(outcomes, dict)
        assert isinstance(faults, dict)
        assert isinstance(oversight, dict)
        counts = {
            "events": evidence_summary["records_unique"],
            "authorization_decisions": denominators["authorization_decisions"],
            "skipped_authorizations": denominators["skipped_authorizations"],
            "execution_outcomes": denominators["execution_outcomes"],
            "denies": outcomes["policy_denies"],
            "errors": faults["total"],
            "reviews": oversight["pending"],
            "gaps": sum(record.event_kind == "collection_gap" for record in records),
        }
        return {
            "counts": counts,
            "authorization_faults": faults,
            "provenance": {
                "source": "stored_events_recent_window",
                "tenant_ref": principal.tenant_ref,
                "rows_summarized": len(records),
                "tenant_event_total": total,
                "truncated": total > len(records),
            },
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return DASHBOARD

    return app


DASHBOARD = """<!doctype html><meta charset="utf-8"><title>Apparitor Observe</title>
<style>
body{font:16px system-ui;max-width:70rem;margin:3rem auto;padding:0 1rem;color:#18202a}
input,button{font:inherit;padding:.6rem}input{width:32rem;max-width:70%}
pre{background:#f3f5f7;padding:1rem;overflow:auto}
</style>
<h1>Observe local reference</h1><p>Enter a reader token. It stays in this page's memory.</p>
<input id="token" type="password" autocomplete="off">
<button id="load">Load summary</button><pre id="result">No data loaded.</pre>
<script>
document.querySelector('#load').onclick=async()=>{
  const out=document.querySelector('#result');out.textContent='Loading…';
  try {
    const token=document.querySelector('#token').value;
    const r=await fetch('/v1/summary',{headers:{Authorization:'Bearer '+token}});
    const body=await r.json();out.textContent=JSON.stringify(body,null,2);
  } catch(e) {out.textContent='Request failed'}
}
</script>"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8765)
