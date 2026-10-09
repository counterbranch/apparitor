from __future__ import annotations

import httpx
import pytest

fastapi = pytest.importorskip("fastapi")

from examples.api.app import Principal, create_app, demo_principal  # noqa: E402

from apparitor import (  # noqa: E402
    AuthorizationEngine,
    EvaluationResponse,
    ScannerConfig,
    Subject,
)
from apparitor.audit import AuditEvidence  # noqa: E402
from apparitor.errors import AuthZENServiceError  # noqa: E402


class Backend:
    def __init__(self, *, unavailable: bool = False) -> None:
        self.unavailable = unavailable

    async def evaluate(self, request):
        if self.unavailable:
            raise AuthZENServiceError("PDP unavailable")
        return EvaluationResponse(decision=request.resource.id in {"allowed", "document-1"})

    async def evaluate_batch(self, request):
        if self.unavailable:
            raise AuthZENServiceError("PDP unavailable")
        return type("Batch", (), {"evaluations": [EvaluationResponse(decision=True)]})()

    async def aclose(self) -> None:
        return None


def app(*, unavailable: bool = False):
    engine = AuthorizationEngine(
        ScannerConfig(agent_id="fixture"),
        client=Backend(unavailable=unavailable),
    )
    return create_app(engine, resolve_principal=demo_principal, audit_key=b"test-key" * 4)


class AuditCollector:
    def __init__(self) -> None:
        self.records: list[AuditEvidence] = []

    def record(self, record: AuditEvidence) -> None:
        self.records.append(record)


async def request(app, body, headers=None):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/authorize", json=body, headers=headers or {})


@pytest.mark.asyncio
async def test_authorized_response_contains_private_fingerprints() -> None:
    response = await request(
        app(),
        {"action": "read", "resource": "allowed", "tenant": "t1", "properties": {"path": "/x"}},
        {"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["status"] == "success"
    assert len(response.json()["request_fingerprint"]) == 16
    assert "path" not in response.text


@pytest.mark.asyncio
async def test_denied_output_matches_http_status() -> None:
    response = await request(
        app(),
        {"action": "read", "resource": "denied", "tenant": "t1"},
        {"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "block"


@pytest.mark.asyncio
async def test_missing_identity_and_tenant_mismatch_are_rejected() -> None:
    body = {"action": "read", "resource": "allowed", "tenant": "t1"}
    assert (await request(app(), body)).status_code == 401
    assert (
        await request(app(), body, {"x-demo-subject": "user-1", "x-demo-tenant": "t2"})
    ).status_code == 403


@pytest.mark.asyncio
async def test_pdp_unavailable_is_service_error() -> None:
    response = await request(
        app(unavailable=True),
        {"action": "read", "resource": "allowed", "tenant": "t1"},
        {"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
    )
    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "error"


@pytest.mark.asyncio
async def test_protected_document_records_execution_and_withholds_denied_content() -> None:
    collector = AuditCollector()
    engine = AuthorizationEngine(
        ScannerConfig(agent_id="fixture"), client=Backend(), audit_sink=collector
    )
    guarded = create_app(
        engine,
        resolve_principal=demo_principal,
        audit_key=b"test-key" * 4,
    )
    transport = httpx.ASGITransport(app=guarded)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        allowed = await client.get(
            "/documents/document-1",
            params={"tenant": "t1"},
            headers={"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
        )
        denied = await client.get(
            "/documents/document-2",
            params={"tenant": "t1"},
            headers={"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
        )
        missing_identity = await client.get("/documents/document-1")
    assert allowed.status_code == 200
    assert allowed.json()["document"] == "synthetic private document"
    assert denied.status_code == 403
    assert "restricted document" not in denied.text
    assert missing_identity.status_code == 401
    assert collector.records[0].event_kind == "aggregate_decision"
    assert collector.records[1].event_kind == "execution_outcome"
    assert collector.records[0].event_id == collector.records[1].event_id
    assert collector.records[2].event_id == collector.records[3].event_id
    assert any(record.execution_status == "succeeded" for record in collector.records)
    assert any(record.execution_status == "not_started" for record in collector.records)


@pytest.mark.asyncio
async def test_protected_document_tenant_and_pdp_failures_do_not_execute() -> None:
    engine = AuthorizationEngine(ScannerConfig(agent_id="fixture"), client=Backend())
    guarded = create_app(
        engine,
        resolve_principal=lambda _: Principal(Subject(type="user", id="user-1"), "t2"),
        audit_key=b"test-key" * 4,
    )
    transport = httpx.ASGITransport(app=guarded)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        tenant_mismatch = await client.get(
            "/documents/document-1",
            params={"tenant": "t1"},
            headers={"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
        )
    unavailable_app = app(unavailable=True)
    transport = httpx.ASGITransport(app=unavailable_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unavailable = await client.get(
            "/documents/document-1",
            params={"tenant": "t1"},
            headers={"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
        )
    assert tenant_mismatch.status_code == 403
    assert unavailable.status_code == 503


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31, "not-bytes"])
def test_evidence_key_requires_32_bytes(key) -> None:
    engine = AuthorizationEngine(ScannerConfig(agent_id="fixture"), client=Backend())
    with pytest.raises(ValueError, match="at least 32 bytes"):
        create_app(engine, resolve_principal=demo_principal, audit_key=key)


@pytest.mark.asyncio
async def test_denied_existing_and_missing_documents_never_access_store(monkeypatch) -> None:
    import examples.api.app as api

    def never_read(document_id):
        raise AssertionError("protected store was accessed before authorization")

    monkeypatch.setattr(api, "_read_demo_document", never_read)
    guarded = app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=guarded), base_url="http://test"
    ) as client:
        headers = {"x-demo-subject": "user-1", "x-demo-tenant": "t1"}
        existing = await client.get("/documents/document-2?tenant=t1", headers=headers)
        missing = await client.get("/documents/missing?tenant=t1", headers=headers)
    assert existing.status_code == missing.status_code == 403
    assert existing.json() == missing.json()


@pytest.mark.asyncio
async def test_client_properties_cannot_supply_authoritative_resource_attributes() -> None:
    class AttributeBackend(Backend):
        async def evaluate(self, evaluation):
            assert evaluation.resource.properties == {}
            assert evaluation.context["requested_properties"] == {"owner": "user-1"}
            return EvaluationResponse(decision=False)

    engine = AuthorizationEngine(ScannerConfig(agent_id="fixture"), client=AttributeBackend())
    guarded = create_app(engine, resolve_principal=demo_principal)
    response = await request(
        guarded,
        {"action": "read", "resource": "denied", "tenant": "t1", "properties": {"owner": "user-1"}},
        {"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_evidence_builder_failure_preserves_authorized_response(monkeypatch) -> None:
    import examples.api.app as api

    def fail_builder(**kwargs):
        raise ValueError("evidence validation failed")

    monkeypatch.setattr(api, "make_audit_evidence", fail_builder)
    engine = AuthorizationEngine(
        ScannerConfig(agent_id="fixture"), client=Backend(), audit_sink=AuditCollector()
    )
    guarded = create_app(engine, resolve_principal=demo_principal, audit_key=b"test-key" * 4)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=guarded), base_url="http://test"
    ) as client:
        response = await client.get(
            "/documents/document-1?tenant=t1",
            headers={"x-demo-subject": "user-1", "x-demo-tenant": "t1"},
        )
    assert response.status_code == 200
    assert response.json()["document"] == "synthetic private document"
