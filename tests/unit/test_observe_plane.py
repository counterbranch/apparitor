from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import threading
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest
import pytest_asyncio

from apparitor import AuthorizationEngine
from apparitor.audit import (
    AuditMetadata,
    JsonLinesAuditSink,
    audit_metadata_scope,
    make_audit_evidence,
    with_execution_outcome,
)

pytest.importorskip("fastapi")

APP_PATH = Path(__file__).parents[2] / "examples" / "observe" / "app.py"
SPEC = importlib.util.spec_from_file_location("observe_app", APP_PATH)
assert SPEC and SPEC.loader
observe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = observe
SPEC.loader.exec_module(observe)

WRITER_A = "writer-a-000000000000000000000000"
READER_A = "reader-a-000000000000000000000000"
WRITER_B = "writer-b-000000000000000000000000"
READER_B = "reader-b-000000000000000000000000"


def event(evidence_id: str, **changes: Any) -> dict[str, Any]:
    metadata = AuditMetadata(
        event_id=f"event-{evidence_id}",
        tenant_ref="tenant-a",
        principal_refs=("actor-a",),
        request_refs=("request-a",),
        policy_id="policy-a",
        policy_version="v1",
        correlation_ref="correlation-a",
        oversight_status="pending",
        trace_id="trace-a",
        action_refs=("read",),
        resource_refs=("record-a",),
        coverage_status="instrumented",
    )
    value = make_audit_evidence(
        event_kind="per_item_decision",
        request_count=1,
        evaluation_status="success",
        metadata=metadata,
        verdict="block",
        latency_ms=2.5,
        cache_status="miss",
    ).to_dict()
    value["evidence_id"] = evidence_id
    value["observed_at"] = "2026-10-09T10:00:00Z"
    value.update(changes)
    return value


@pytest_asyncio.fixture
async def client(tmp_path: Path):
    credentials = {
        WRITER_A: observe.Credential(tenant_ref="tenant-a", role="writer"),
        READER_A: observe.Credential(tenant_ref="tenant-a", role="reader"),
        WRITER_B: observe.Credential(tenant_ref="tenant-b", role="writer"),
        READER_B: observe.Credential(tenant_ref="tenant-b", role="reader"),
    }
    app = observe.create_app(database_path=tmp_path / "observe.db", credentials=credentials)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as test_client,
    ):
        yield test_client


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_auth_roles_and_tenant_isolation(client: httpx.AsyncClient) -> None:
    unauthenticated = await client.post("/v1/events:ingest", json={"events": [event("a")]})
    assert unauthenticated.status_code == 401
    assert (
        await client.post(
            "/v1/events:ingest", json={"events": [event("a")]}, headers=auth(READER_A)
        )
    ).status_code == 403
    assert (
        await client.post(
            "/v1/events:ingest",
            json={"events": [event("b", tenant_ref="tenant-b")]},
            headers=auth(WRITER_A),
        )
    ).status_code == 403
    assert (
        await client.post(
            "/v1/events:ingest", json={"events": [event("a")]}, headers=auth(WRITER_A)
        )
    ).status_code == 200
    assert (await client.get("/v1/events", headers=auth(WRITER_A))).status_code == 403
    assert (await client.get("/v1/events", headers=auth(READER_B))).json()["total"] == 0
    assert (
        await client.get("/v1/events?tenant_ref=tenant-b", headers=auth(READER_A))
    ).status_code == 403


@pytest.mark.asyncio
async def test_idempotency_conflict_and_validation(client: httpx.AsyncClient) -> None:
    payload = {"events": [event("same")]}
    first = await client.post("/v1/events:ingest", json=payload, headers=auth(WRITER_A))
    second = await client.post("/v1/events:ingest", json=payload, headers=auth(WRITER_A))
    assert first.json() == second.json() == {"acknowledged_ids": ["same"]}
    conflict = await client.post(
        "/v1/events:ingest",
        json={"events": [event("same", verdict="allow")]},
        headers=auth(WRITER_A),
    )
    assert conflict.status_code == 409
    unknown = event("unknown")
    unknown["raw_secret"] = "do-not-store"
    assert (
        await client.post("/v1/events:ingest", json={"events": [unknown]}, headers=auth(WRITER_A))
    ).status_code == 422
    too_large = event("large", action_refs=["x" * 300])
    assert (
        await client.post("/v1/events:ingest", json={"events": [too_large]}, headers=auth(WRITER_A))
    ).status_code == 422


@pytest.mark.asyncio
async def test_filters_timeline_summary_alerts_and_sanitized_detail(
    client: httpx.AsyncClient,
) -> None:
    later = event(
        "later",
        observed_at="2026-10-09T11:00:00Z",
        verdict="allow",
        coverage_status="unknown",
    )
    earlier = event("earlier", observed_at="2026-10-09T09:00:00Z")
    response = await client.post(
        "/v1/events:ingest", json={"events": [later, earlier]}, headers=auth(WRITER_A)
    )
    assert response.status_code == 200

    filtered = await client.get(
        "/v1/events?actor=actor-a&action=read&resource=record-a&policy=policy-a&outcome=block&limit=1",
        headers=auth(READER_A),
    )
    assert filtered.json()["total"] == 1
    timeline = await client.get("/v1/traces/trace-a", headers=auth(READER_A))
    assert [item["evidence_id"] for item in timeline.json()["items"]] == ["earlier", "later"]
    summary = (await client.get("/v1/summary", headers=auth(READER_A))).json()
    assert summary["counts"] == {
        "events": 2,
        "authorization_decisions": 2,
        "skipped_authorizations": 0,
        "execution_outcomes": 0,
        "denies": 1,
        "errors": 0,
        "reviews": 2,
        "gaps": 0,
    }
    alerts = (await client.get("/v1/alerts", headers=auth(READER_A))).json()
    assert {item["reason"] for item in alerts["items"]} == {"policy_block", "collection_gap"}
    assert alerts["classification"] == "operational_signal_not_statutory_incident"
    detail = (await client.get("/v1/events/earlier", headers=auth(READER_A))).json()
    assert "raw_secret" not in detail


@pytest.mark.asyncio
async def test_summary_separates_decision_from_execution(client: httpx.AsyncClient) -> None:
    decision = event("decision")
    parsed = observe.AuditEvidence.from_dict(json.loads(json.dumps(decision)))
    execution = with_execution_outcome(parsed, "succeeded").to_dict()
    execution["evidence_id"] = "execution"
    response = await client.post(
        "/v1/events:ingest",
        json={"events": [decision, execution]},
        headers=auth(WRITER_A),
    )
    assert response.status_code == 200
    counts = (await client.get("/v1/summary", headers=auth(READER_A))).json()["counts"]
    assert counts["authorization_decisions"] == 1
    assert counts["execution_outcomes"] == 1
    assert counts["denies"] == 1
    assert counts["errors"] == 0
    alerts = (await client.get("/v1/alerts", headers=auth(READER_A))).json()["items"]
    assert [alert["reason"] for alert in alerts] == ["policy_block"]


@pytest.mark.asyncio
async def test_ingest_and_read_database_operations_share_event_loop_thread(
    client: httpx.AsyncClient,
) -> None:
    app = client._transport.app  # type: ignore[attr-defined]
    database_threads: set[int] = set()
    app.state.db.set_trace_callback(lambda statement: database_threads.add(threading.get_ident()))

    assert (
        await client.post(
            "/v1/events:ingest", json={"events": [event("threaded")]}, headers=auth(WRITER_A)
        )
    ).status_code == 200
    assert (await client.get("/v1/events?limit=1", headers=auth(READER_A))).status_code == 200
    assert (await client.get("/v1/events/threaded", headers=auth(READER_A))).status_code == 200
    assert (await client.get("/v1/summary", headers=auth(READER_A))).status_code == 200
    assert database_threads == {threading.get_ident()}


@pytest.mark.asyncio
async def test_concurrent_ingest_queries_and_conflicts_preserve_transactions(
    client: httpx.AsyncClient,
) -> None:
    seed = event("same")
    assert (
        await client.post("/v1/events:ingest", json={"events": [seed]}, headers=auth(WRITER_A))
    ).status_code == 200

    async def ingest(number: int) -> None:
        records = (
            [seed, event(f"new-{number}")]
            if number % 2 == 0
            else [event(f"rolledback-{number}"), event("same", verdict="allow")]
        )
        response = await client.post(
            "/v1/events:ingest", json={"events": records}, headers=auth(WRITER_A)
        )
        assert response.status_code == (200 if number % 2 == 0 else 409)

    async def query() -> None:
        for route in ("/v1/events", "/v1/traces/trace-a", "/v1/summary"):
            assert (await client.get(route, headers=auth(READER_A))).status_code == 200

    await asyncio.gather(*(ingest(number) for number in range(40)), *(query() for _ in range(20)))
    result = (await client.get("/v1/events?limit=100", headers=auth(READER_A))).json()
    assert result["total"] == 21
    assert not any(item["evidence_id"].startswith("rolledback") for item in result["items"])


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [{}, {"Content-Length": "1"}])
async def test_streaming_body_limit_does_not_trust_content_length(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    async def oversized():
        chunk = b"x" * observe.MAX_EVENT_BYTES
        for _ in range(observe.MAX_BATCH_EVENTS + 1):
            yield chunk

    response = await client.post(
        "/v1/events:ingest",
        content=oversized(),
        headers={**auth(WRITER_A), **headers},
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_list_and_trace_decode_only_requested_page(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [event(f"event-{number:02}") for number in range(20)]
    assert (
        await client.post("/v1/events:ingest", json={"events": records}, headers=auth(WRITER_A))
    ).status_code == 200
    decoded = 0
    original = observe._decode_event

    def count_decode(value: str):
        nonlocal decoded
        decoded += 1
        return original(value)

    monkeypatch.setattr(observe, "_decode_event", count_decode)
    listing = await client.get("/v1/events?limit=1", headers=auth(READER_A))
    assert listing.json()["total"] == 20
    assert decoded == 1
    timeline = await client.get("/v1/traces/trace-a?limit=2&offset=1", headers=auth(READER_A))
    assert timeline.json()["total"] == 20
    assert len(timeline.json()["items"]) == 2
    assert decoded == 3


@pytest.mark.asyncio
async def test_summary_window_is_explicit_and_faults_are_not_decisions(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    mapping = event(
        "mapping",
        event_kind="mapping_failure",
        evaluation_status="error",
        error_code="mapping_failed",
    )
    cancelled = event(
        "cancelled", event_kind="cancelled", evaluation_status="skipped", verdict="skip"
    )
    records = [mapping, cancelled]
    assert (
        await client.post("/v1/events:ingest", json={"events": records}, headers=auth(WRITER_A))
    ).status_code == 200
    fault_summary = (await client.get("/v1/summary", headers=auth(READER_A))).json()
    assert fault_summary["counts"]["authorization_decisions"] == 0
    assert fault_summary["counts"]["errors"] == 2
    fault_alerts = (await client.get("/v1/alerts", headers=auth(READER_A))).json()["items"]
    assert {item["reason"] for item in fault_alerts} == {
        "mapping_failure",
        "authorization_cancelled",
    }
    assert (
        await client.post(
            "/v1/events:ingest",
            json={"events": [event("decision"), event("extra")]},
            headers=auth(WRITER_A),
        )
    ).status_code == 200
    monkeypatch.setattr(observe, "MAX_SUMMARY_EVENTS", 3)
    summary = (await client.get("/v1/summary", headers=auth(READER_A))).json()
    assert summary["provenance"] == {
        "source": "stored_events_recent_window",
        "tenant_ref": "tenant-a",
        "rows_summarized": 3,
        "tenant_event_total": 4,
        "truncated": True,
    }
    alerts = (await client.get("/v1/alerts", headers=auth(READER_A))).json()
    assert alerts["sample"]["truncated"] is True

    monkeypatch.setattr(observe, "MAX_SUMMARY_EVENTS", 10)
    complete = (await client.get("/v1/summary", headers=auth(READER_A))).json()
    assert complete["counts"]["authorization_decisions"] == 2
    assert complete["counts"]["errors"] == 2
    reasons = {
        item["reason"]
        for item in (await client.get("/v1/alerts", headers=auth(READER_A))).json()["items"]
    }
    assert {"mapping_failure", "authorization_cancelled"} <= reasons


@pytest.mark.asyncio
async def test_engine_boundary_refusal_and_skip_remain_distinct_in_http_summary(
    client: httpx.AsyncClient, make_config
) -> None:
    stream = StringIO()
    engine = AuthorizationEngine(make_config(), audit_sink=JsonLinesAuditSink(stream))
    try:
        with audit_metadata_scope(AuditMetadata("boundary-request", "tenant-a")):
            engine.record_refusal("unsupported_execution_route")
    finally:
        await engine.aclose()
    refusal = json.loads(stream.getvalue())
    assert refusal["event_kind"] == "boundary_refusal"
    records = [
        refusal,
        event("mapping", event_kind="mapping_failure", evaluation_status="error"),
        event("skip", event_kind="aggregate_decision", verdict="skip", evaluation_status="skipped"),
    ]
    response = await client.post(
        "/v1/events:ingest", json={"events": records}, headers=auth(WRITER_A)
    )
    assert response.status_code == 200
    summary = (await client.get("/v1/summary", headers=auth(READER_A))).json()
    assert summary["counts"]["authorization_decisions"] == 0
    assert summary["counts"]["skipped_authorizations"] == 1
    assert summary["authorization_faults"] == {
        "evaluation_errors": 0,
        "mapping_failures": 1,
        "boundary_refusals": 1,
        "cancellations": 0,
        "total": 2,
    }
    alerts = (await client.get("/v1/alerts", headers=auth(READER_A))).json()["items"]
    assert {item["reason"] for item in alerts} == {"mapping_failure", "boundary_refused"}


def test_database_permissions_and_symlink_rejection(tmp_path: Path) -> None:
    database = tmp_path / "observe.db"
    credentials = {WRITER_A: observe.Credential(tenant_ref="tenant-a", role="writer")}
    app = observe.create_app(database_path=database, credentials=credentials)

    async def open_database() -> None:
        async with app.router.lifespan_context(app):
            assert {path.stat().st_mode & 0o777 for path in tmp_path.glob("observe.db*")} == {0o600}

    import asyncio

    asyncio.run(open_database())
    target = tmp_path / "target.db"
    target.touch(mode=0o600)
    link = tmp_path / "link.db"
    os.symlink(target, link)
    linked_app = observe.create_app(database_path=link, credentials=credentials)

    async def open_link() -> None:
        async with linked_app.router.lifespan_context(linked_app):
            pass

    with pytest.raises(ValueError, match="regular file"):
        asyncio.run(open_link())
