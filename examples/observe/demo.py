"""Run an entirely local authorization-to-Observe pipeline."""

from __future__ import annotations

import asyncio
import json
import secrets
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

import httpx

from apparitor.audit import (
    AuditEvidence,
    AuditMetadata,
    audit_metadata_scope,
    with_execution_outcome,
)
from apparitor.collector import DeliveryEvent, DeliveryResult, LocalAuditCollector
from apparitor.config import ScannerConfig
from apparitor.decision import Verdict
from apparitor.engine import AuthorizationEngine
from apparitor.models import (
    Action,
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    EvaluationRequest,
    EvaluationResponse,
    Resource,
    Subject,
)

from .app import Credential, create_app

TENANT_REF = "tenant_demo_opaque"
TRACE_REF = "trace_demo_opaque"


class SyntheticBackend:
    """Local policy: permit resources whose opaque ID begins with ``allowed``."""

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        return EvaluationResponse(decision=request.resource.id.startswith("allowed"))

    async def evaluate_batch(self, request: BatchEvaluationRequest) -> BatchEvaluationResponse:
        decisions = [
            EvaluationResponse(decision=item.resource.id.startswith("allowed"))
            for item in request.evaluations
            if item.resource is not None
        ]
        return BatchEvaluationResponse(evaluations=decisions)

    async def aclose(self) -> None:
        return None


@dataclass
class RecordingSink:
    collector: LocalAuditCollector
    latest: AuditEvidence | None = None

    def record(self, record: AuditEvidence) -> None:
        self.collector.record(record)
        self.latest = record


def metadata(event_id: str) -> AuditMetadata:
    return AuditMetadata(
        event_id=event_id,
        tenant_ref=TENANT_REF,
        principal_refs=("principal_demo_opaque",),
        request_refs=(f"request_{event_id}",),
        policy_id="demo-policy",
        policy_version="sha256:demo-v1",
        trace_id=TRACE_REF,
        user_ref="user_demo_opaque",
        agent_ref="agent_demo_opaque",
        integration="observe-local-demo",
        action_refs=("document.read",),
        resource_refs=(f"resource_{event_id}",),
        coverage_status="instrumented",
    )


async def generate_evidence(collector: LocalAuditCollector) -> tuple[str, str]:
    sink = RecordingSink(collector)
    engine = AuthorizationEngine(
        ScannerConfig(agent_id="demo-agent"), client=SyntheticBackend(), audit_sink=sink
    )
    verdicts: list[str] = []
    for event_id, resource_id in (("allow", "allowed-report"), ("block", "restricted-report")):
        request = EvaluationRequest(
            subject=Subject(type="user", id="trusted-demo-user"),
            action=Action(name="document.read"),
            resource=Resource(type="document", id=resource_id),
        )
        with audit_metadata_scope(metadata(event_id)):
            result = await engine.evaluate_requests([request])
        verdicts.append(result.verdict.value)
        assert sink.latest is not None
        status: Literal["succeeded", "not_started"] = (
            "succeeded" if result.verdict is Verdict.ALLOW else "not_started"
        )
        collector.record(
            with_execution_outcome(
                sink.latest,
                status,
                observed_at=datetime.now(timezone.utc),
                outcome_ref=f"outcome_{event_id}",
            )
        )
    await engine.aclose()
    return verdicts[0], verdicts[1]


def asgi_transport(
    client: httpx.AsyncClient,
) -> Callable[[tuple[DeliveryEvent, ...]], Awaitable[DeliveryResult]]:
    async def send(events: tuple[DeliveryEvent, ...]) -> DeliveryResult:
        if not 1 <= len(events) <= 100:
            raise ValueError("Observe batches must contain 1..100 events")
        sent = {event.evidence_id for event in events}
        response = await client.post(
            "/v1/events:ingest",
            json={"events": [json.loads(event.payload) for event in events]},
        )
        response.raise_for_status()
        body = cast(dict[str, list[str]], response.json())
        acknowledged = frozenset(body["acknowledged_ids"])
        if acknowledged != sent:
            raise ValueError("Observe acknowledgement IDs do not match the sent batch")
        return DeliveryResult(acknowledged)

    return send


async def run_pipeline(root: Path, *, lose_first_ack: bool = False) -> dict[str, Any]:
    writer_token, reader_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    credentials = {
        writer_token: Credential(tenant_ref=TENANT_REF, role="writer"),
        reader_token: Credential(tenant_ref=TENANT_REF, role="reader"),
    }
    outbox_path = root / "outbox.sqlite3"
    collector = LocalAuditCollector(outbox_path)
    verdicts = await generate_evidence(collector)
    collector.close()
    collector = LocalAuditCollector(outbox_path)

    app = create_app(database_path=root / "observe.sqlite3", credentials=credentials)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://observe.local") as raw:
            writer = httpx.AsyncClient(
                transport=transport,
                base_url="http://observe.local",
                headers={"authorization": f"Bearer {writer_token}"},
            )
            delivery = asgi_transport(writer)
            lost = False

            async def maybe_lose_ack(events: tuple[DeliveryEvent, ...]) -> DeliveryResult:
                nonlocal lost
                result = await delivery(events)
                if lose_first_ack and not lost:
                    lost = True
                    raise OSError("synthetic lost acknowledgement")
                return result

            flush = await collector.flush(maybe_lose_ack, base_backoff=0)
            await writer.aclose()
            headers = {"authorization": f"Bearer {reader_token}"}
            summary = (await raw.get("/v1/summary", headers=headers)).json()
            timeline = (await raw.get(f"/v1/traces/{TRACE_REF}", headers=headers)).json()
            alerts = (await raw.get("/v1/alerts", headers=headers)).json()
    status = collector.status()
    collector.close()
    return {
        "verdicts": verdicts,
        "flush": flush,
        "collector": status,
        "summary": summary,
        "timeline": timeline,
        "alerts": alerts,
    }


async def main() -> None:
    with tempfile.TemporaryDirectory(prefix="apparitor-observe-") as directory:
        result = await run_pipeline(Path(directory), lose_first_ack=True)
        print(
            json.dumps(
                {
                    "pending": result["collector"].pending,
                    "delivered": result["collector"].delivered,
                    "retries": result["collector"].retries,
                    "summary": result["summary"]["counts"],
                    "timeline_events": len(result["timeline"]["items"]),
                    "alerts": len(result["alerts"]["items"]),
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
