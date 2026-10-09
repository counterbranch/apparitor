"""A local FastAPI boundary around apparitor's existing ``evaluate_requests`` seam.

This example's ``demo_principal`` is a fixture only. A deployed host must replace it with
an authentication dependency that has already verified the credential and resolved the
principal; this sample never decodes tokens.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from apparitor import (
    Action,
    AuthorizationEngine,
    EvaluationRequest,
    Resource,
    ScannerConfig,
    Subject,
)
from apparitor.audit import (
    AuditMetadata,
    audit_metadata_scope,
    make_audit_evidence,
    with_execution_outcome,
)

try:
    from fastapi import FastAPI, HTTPException, Request
    from pydantic import BaseModel, ConfigDict, Field
except ImportError as exc:  # pragma: no cover - exercised by the install guard, not unit logic
    raise RuntimeError(
        "The API example needs FastAPI; install examples/api/requirements.txt"
    ) from exc


@dataclass(frozen=True)
class Principal:
    subject: Subject
    tenant: str


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=500)
    tenant: str = Field(min_length=1, max_length=200)
    properties: dict[str, Any] = Field(default_factory=dict)


def demo_principal(request: Request) -> Principal | None:
    """Fixture auth resolver; headers stand in for an already verified identity."""
    subject_id = request.headers.get("x-demo-subject")
    tenant = request.headers.get("x-demo-tenant")
    if not subject_id or not tenant:
        return None
    return Principal(Subject(type="user", id=subject_id), tenant)


logger = logging.getLogger("apparitor.api.example")


def _opaque_ref(key: bytes, *values: str) -> str:
    canonical = json.dumps(values, separators=(",", ":")).encode()
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()[:24]


def _fingerprint(request: EvaluationRequest, key: bytes) -> str:
    encoded = json.dumps(
        request.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()[:16]


def _output_fingerprint(payload: dict[str, Any], key: bytes) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()[:16]


def _read_demo_document(document_id: str) -> str | None:
    return {
        "document-1": "synthetic private document",
        "document-2": "synthetic restricted document",
    }.get(document_id)


def create_app(
    engine: AuthorizationEngine,
    *,
    resolve_principal: Callable[[Request], Principal | None],
    audit_key: bytes | None = None,
) -> FastAPI:
    """Build an app that reuses one long-lived engine and closes it with the app.

    ``resolve_principal`` is required so a deployer cannot accidentally ship the fixture
    resolver. When the engine has an audit sink, ``audit_key`` must be an app-held secret
    used only to derive opaque evidence references.
    """
    if audit_key is not None and (not isinstance(audit_key, bytes) or len(audit_key) < 32):
        raise ValueError("audit_key must contain at least 32 bytes")
    if engine.audit_sink is not None and audit_key is None:
        raise ValueError("audit_key is required when audit_sink is configured")
    fingerprint_key = audit_key if audit_key is not None else secrets.token_bytes(32)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            await engine.aclose()

    app = FastAPI(title="apparitor authorization example", lifespan=lifespan)

    @app.post("/authorize")
    async def authorize(body: ActionInput, request: Request) -> dict[str, Any]:
        principal = resolve_principal(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="authenticated principal required")
        if body.tenant != principal.tenant:
            raise HTTPException(
                status_code=403, detail="tenant does not match authenticated principal"
            )

        evaluation = EvaluationRequest(
            subject=principal.subject,
            action=Action(name=body.action),
            resource=Resource(type="api_resource", id=body.resource),
            context={
                "tenant": principal.tenant,
                "correlation_id": str(uuid4()),
            },
        )
        with audit_metadata_scope(
            AuditMetadata(
                event_id=f"evt_{uuid4().hex}",
                tenant_ref=_opaque_ref(audit_key, "tenant", principal.tenant)
                if audit_key
                else "example",
                principal_refs=(
                    _opaque_ref(
                        audit_key,
                        "principal",
                        principal.tenant,
                        principal.subject.type,
                        principal.subject.id,
                    )
                    if audit_key
                    else "example",
                ),
                request_refs=(uuid4().hex,),
                correlation_ref=evaluation.context["correlation_id"],
            )
        ):
            result = await engine.evaluate_requests([evaluation])
        request_fp = _fingerprint(evaluation, fingerprint_key)
        payload: dict[str, Any] = {
            "decision": result.verdict.value,
            "status": result.status.value,
            "request_fingerprint": request_fp,
        }
        payload["output_fingerprint"] = _output_fingerprint(payload, fingerprint_key)
        if result.status.value == "error":
            raise HTTPException(status_code=503, detail=payload)
        if result.verdict.value != "allow" or result.status.value != "success":
            raise HTTPException(status_code=403, detail=payload)
        return payload

    @app.get("/documents/{document_id}")
    async def read_document(document_id: str, request: Request) -> dict[str, Any]:
        """Gate a synthetic document and record whether content execution occurred."""
        principal = resolve_principal(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="authenticated principal required")
        requested_tenant = request.query_params.get("tenant")
        if requested_tenant != principal.tenant:
            raise HTTPException(
                status_code=403, detail="tenant does not match authenticated principal"
            )
        evaluation = EvaluationRequest(
            subject=principal.subject,
            action=Action(name="document.read"),
            resource=Resource(type="document", id=document_id),
            context={"tenant": principal.tenant, "correlation_id": str(uuid4())},
        )
        metadata = AuditMetadata(
            event_id=f"evt_{uuid4().hex}",
            tenant_ref=_opaque_ref(audit_key, "tenant", principal.tenant)
            if audit_key
            else "example",
            principal_refs=(
                _opaque_ref(
                    audit_key,
                    "principal",
                    principal.tenant,
                    principal.subject.type,
                    principal.subject.id,
                )
                if audit_key
                else "example",
            ),
            request_refs=(uuid4().hex,),
            correlation_ref=evaluation.context["correlation_id"],
        )
        with audit_metadata_scope(metadata):
            result = await engine.evaluate_requests([evaluation])
        document = None
        if result.status.value == "error":
            execution_status = "not_started"
            status_code = 503
        elif result.verdict.value != "allow" or result.status.value != "success":
            execution_status = "not_started"
            status_code = 403
        else:
            document = _read_demo_document(document_id)
            execution_status = "succeeded" if document is not None else "failed"
            status_code = 200 if document is not None else 404
        if engine.audit_sink is not None:
            try:
                decision_record = make_audit_evidence(
                    event_kind="aggregate_decision",
                    request_count=1,
                    evaluation_status=result.status.value,
                    verdict=result.verdict.value,
                    metadata=metadata,
                )
                engine.audit_sink.record(
                    with_execution_outcome(
                        decision_record,
                        execution_status,
                        outcome_ref=_opaque_ref(
                            audit_key, "outcome", principal.tenant, document_id, execution_status
                        ),
                    )
                )
            except (Exception, asyncio.CancelledError):
                logger.warning("apparitor API execution evidence sink failed")
        if status_code != 200:
            raise HTTPException(
                status_code=status_code,
                detail={"decision": result.verdict.value, "status": result.status.value},
            )
        return {"decision": "allow", "status": "success", "document": document}

    return app


class DemoBackend:
    """Dependency-free backend for the loopback demo; real hosts inject their backend."""

    async def evaluate(self, request: EvaluationRequest):
        from apparitor.models import EvaluationResponse

        return EvaluationResponse(decision=request.resource.id in {"allowed", "document-1"})

    async def evaluate_batch(self, request):
        from apparitor.models import BatchEvaluationResponse, EvaluationResponse

        return BatchEvaluationResponse(
            evaluations=[EvaluationResponse(decision=True) for _ in request.evaluations]
        )

    async def aclose(self) -> None:
        return None


def create_demo_app() -> FastAPI:
    engine = AuthorizationEngine(ScannerConfig(agent_id="demo"), client=DemoBackend())
    return create_app(
        engine,
        resolve_principal=demo_principal,
        audit_key=secrets.token_bytes(32),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_demo_app(), host="127.0.0.1", port=8000)
