from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")

from examples.observe.demo import TENANT_REF, asgi_transport, run_pipeline

from apparitor.audit import AuditMetadata, make_audit_evidence
from apparitor.collector import DeliveryEvent, LocalAuditCollector

pytestmark = pytest.mark.unit


def _delivery_event() -> DeliveryEvent:
    evidence = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        evaluation_status="error",
        metadata=AuditMetadata(event_id="transport", tenant_ref=TENANT_REF),
    )
    return DeliveryEvent(evidence.evidence_id, evidence.to_json().encode())


@pytest.mark.asyncio
async def test_real_pipeline_survives_reopen_and_lost_ack_without_double_count(
    tmp_path: Path,
) -> None:
    result = await run_pipeline(tmp_path, lose_first_ack=True)

    assert result["verdicts"] == ("allow", "block")
    assert result["collector"].pending == 0
    assert result["collector"].retries == 4
    assert result["summary"]["counts"] == {
        "events": 4,
        "authorization_decisions": 2,
        "skipped_authorizations": 0,
        "execution_outcomes": 2,
        "denies": 1,
        "errors": 0,
        "reviews": 0,
        "gaps": 0,
    }
    assert len(result["timeline"]["items"]) == 4
    assert [item["reason"] for item in result["alerts"]["items"]] == ["policy_block"]
    assert all(item["tenant_ref"] == TENANT_REF for item in result["timeline"]["items"])
    assert all(
        item["schema_version"] == "apparitor.audit/v1" for item in result["timeline"]["items"]
    )


@pytest.mark.asyncio
async def test_transport_rejects_unbounded_batch_before_request() -> None:
    class NeverCalled:
        async def post(self, *args, **kwargs):
            raise AssertionError("request should not be sent")

    event = _delivery_event()
    with pytest.raises(ValueError, match=r"1\.\.100"):
        await asgi_transport(NeverCalled())((event,) * 101)


@pytest.mark.asyncio
async def test_transport_rejects_acknowledgement_for_unsent_id() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"acknowledged_ids": ["other"]})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://observe.local"
    ) as client:
        with pytest.raises(ValueError, match="do not match"):
            await asgi_transport(client)((_delivery_event(),))


@pytest.mark.asyncio
async def test_reopen_preserves_real_pending_evidence(tmp_path: Path) -> None:
    path = tmp_path / "pending.sqlite3"
    collector = LocalAuditCollector(path)
    evidence = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        evaluation_status="error",
        metadata=AuditMetadata(event_id="evt", tenant_ref=TENANT_REF),
    )
    collector.record(evidence)
    collector.close()

    reopened = LocalAuditCollector(path)
    assert reopened.status().pending == 1
    assert reopened.status().pending_bytes == len(evidence.to_json().encode())
    assert json.loads(evidence.to_json())["schema_version"] == "apparitor.audit/v1"
    reopened.close()
