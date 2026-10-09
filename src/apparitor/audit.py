"""Privacy-bounded evidence records for authorization and execution events.

The host supplies opaque, tenant-scoped references.  This module never derives an
identity from an AuthZEN request and never serialises request properties or context.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import MISSING, asdict, dataclass, fields, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, TextIO, cast, runtime_checkable

from .adapters import NormalizedToolCall
from .decision import VerdictResult
from .models import EvaluationRequest

EventKind = Literal[
    "aggregate_decision",
    "per_item_decision",
    "mapping_failure",
    "boundary_refusal",
    "cancelled",
    "execution_outcome",
    "collection_gap",
]
CacheStatus = Literal["not_applicable", "unknown", "hit", "miss"]
OversightStatus = Literal["not_required", "not_observed", "pending", "approved", "rejected"]
ExecutionStatus = Literal["not_observed", "not_started", "succeeded", "failed", "cancelled"]
CoverageStatus = Literal["instrumented", "unknown"]

_NOT_COLLECTED = (
    "credentials",
    "direct_principal_identifiers",
    "prompt_or_response_content",
    "protected_attributes",
    "raw_request_arguments",
    "raw_request_context",
)
_MAX_REFS = 64
_MAX_REQUEST_COUNT = 1_000_000
_MAX_FINGERPRINT_BYTES = 1_000_000
_MAX_TEXT = 256
_EVENT_KINDS = {
    "aggregate_decision",
    "per_item_decision",
    "mapping_failure",
    "boundary_refusal",
    "cancelled",
    "execution_outcome",
    "collection_gap",
}
_CACHE_STATUSES = {"not_applicable", "unknown", "hit", "miss"}
_OVERSIGHT_STATUSES = {"not_required", "not_observed", "pending", "approved", "rejected"}
_EXECUTION_STATUSES = {"not_observed", "not_started", "succeeded", "failed", "cancelled"}
_COVERAGE_STATUSES = {"instrumented", "unknown"}
_VERDICTS = {"allow", "block", "human_review", "skip"}
_EVALUATION_STATUSES = {"success", "error", "skipped"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_text(name: str, value: str | None, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise ValueError(f"{name} is required")
        return
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value or len(value) > _MAX_TEXT or any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{name} must be 1..{_MAX_TEXT} printable characters")


def _validate_refs(name: str, refs: tuple[str, ...]) -> None:
    if not isinstance(refs, tuple):
        raise TypeError(f"{name} must be a tuple")
    if len(refs) > _MAX_REFS:
        raise ValueError(f"{name} must contain at most {_MAX_REFS} references")
    for ref in refs:
        _validate_text(name, ref, required=True)


def _normalise_time(value: datetime | None) -> datetime:
    observed = value or _utc_now()
    if not isinstance(observed, datetime):
        raise TypeError("observed_at must be a datetime")
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")
    return observed.astimezone(timezone.utc)


def _validate_rfc3339(name: str, value: str | None) -> None:
    if value is None:
        return
    _validate_text(name, value, required=True)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{name} must be UTC")
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be UTC in canonical Z notation")


@dataclass(frozen=True)
class AuditMetadata:
    """Trusted host metadata; all ``*_ref`` values must already be opaque."""

    event_id: str
    tenant_ref: str
    principal_refs: tuple[str, ...] = ()
    request_refs: tuple[str, ...] = ()
    policy_id: str | None = None
    policy_version: str | None = None
    correlation_ref: str | None = None
    observed_at: datetime | None = None
    oversight_status: OversightStatus = "not_observed"
    trace_id: str | None = None
    run_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    call_id: str | None = None
    session_ref: str | None = None
    device_ref: str | None = None
    user_ref: str | None = None
    agent_ref: str | None = None
    workload_ref: str | None = None
    integration: str | None = None
    action_refs: tuple[str, ...] = ()
    resource_refs: tuple[str, ...] = ()
    argument_fingerprints: tuple[str, ...] = ()
    reason_code: str | None = None
    coverage_status: CoverageStatus | None = None

    def __post_init__(self) -> None:
        _validate_text("event_id", self.event_id, required=True)
        _validate_text("tenant_ref", self.tenant_ref, required=True)
        _validate_refs("principal_refs", self.principal_refs)
        _validate_refs("request_refs", self.request_refs)
        for name in (
            "policy_id",
            "policy_version",
            "correlation_ref",
            "trace_id",
            "run_id",
            "span_id",
            "parent_span_id",
            "call_id",
            "session_ref",
            "device_ref",
            "user_ref",
            "agent_ref",
            "workload_ref",
            "integration",
            "reason_code",
        ):
            _validate_text(name, getattr(self, name))
        for name in ("action_refs", "resource_refs", "argument_fingerprints"):
            _validate_refs(name, getattr(self, name))
        if (self.policy_id is None) != (self.policy_version is None):
            raise ValueError("policy_id and policy_version must be supplied together")
        if self.oversight_status not in _OVERSIGHT_STATUSES:
            raise ValueError("invalid oversight_status")
        if self.coverage_status is not None and self.coverage_status not in _COVERAGE_STATUSES:
            raise ValueError("invalid coverage_status")
        if self.parent_span_id is not None and self.span_id is None:
            raise ValueError("parent_span_id requires span_id")
        if self.observed_at is not None:
            _normalise_time(self.observed_at)


@dataclass(frozen=True)
class AuditEvidence:
    """A bounded, JSON-safe observation; it does not attest legal compliance."""

    schema_version: str
    event_kind: EventKind
    evidence_id: str
    event_id: str
    observed_at: str
    tenant_ref: str
    principal_refs: tuple[str, ...]
    request_refs: tuple[str, ...]
    request_count: int
    policy_id: str | None
    policy_version: str | None
    correlation_ref: str | None
    verdict: str | None
    evaluation_status: str
    latency_ms: float | None
    cache_status: CacheStatus
    oversight_status: OversightStatus
    error_code: str | None
    execution_status: ExecutionStatus = "not_observed"
    execution_observed_at: str | None = None
    execution_outcome_ref: str | None = None
    trace_id: str | None = None
    run_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    call_id: str | None = None
    session_ref: str | None = None
    device_ref: str | None = None
    user_ref: str | None = None
    agent_ref: str | None = None
    workload_ref: str | None = None
    integration: str | None = None
    action_refs: tuple[str, ...] = ()
    resource_refs: tuple[str, ...] = ()
    argument_fingerprints: tuple[str, ...] = ()
    reason_code: str | None = None
    coverage_status: CoverageStatus | None = None
    not_collected: tuple[str, ...] = _NOT_COLLECTED

    def __post_init__(self) -> None:
        for name in (
            "schema_version",
            "evidence_id",
            "event_id",
            "observed_at",
            "tenant_ref",
            "evaluation_status",
        ):
            _validate_text(name, getattr(self, name), required=True)
        for name in (
            "policy_id",
            "policy_version",
            "correlation_ref",
            "verdict",
            "error_code",
            "execution_observed_at",
            "execution_outcome_ref",
            "trace_id",
            "run_id",
            "span_id",
            "parent_span_id",
            "call_id",
            "session_ref",
            "device_ref",
            "user_ref",
            "agent_ref",
            "workload_ref",
            "integration",
            "reason_code",
        ):
            _validate_text(name, getattr(self, name))
        _validate_refs("principal_refs", self.principal_refs)
        _validate_refs("request_refs", self.request_refs)
        _validate_refs("not_collected", self.not_collected)
        _validate_refs("action_refs", self.action_refs)
        _validate_refs("resource_refs", self.resource_refs)
        _validate_refs("argument_fingerprints", self.argument_fingerprints)
        if self.event_kind not in _EVENT_KINDS:
            raise ValueError("invalid event_kind")
        if self.schema_version != "apparitor.audit/v1":
            raise ValueError("invalid schema_version")
        if self.verdict is not None and self.verdict not in _VERDICTS:
            raise ValueError("invalid verdict")
        allowed_statuses = (
            _EVALUATION_STATUSES | {"not_observed"}
            if self.event_kind == "collection_gap"
            else _EVALUATION_STATUSES
        )
        if self.evaluation_status not in allowed_statuses:
            raise ValueError("invalid evaluation_status")
        if self.event_kind == "collection_gap":
            if self.evaluation_status != "not_observed" or self.verdict is not None:
                raise ValueError("collection gaps require not_observed status and no verdict")
        elif (self.verdict == "skip") != (self.evaluation_status == "skipped"):
            raise ValueError("skip verdict requires evaluation_status=skipped")
        if self.cache_status not in _CACHE_STATUSES:
            raise ValueError("invalid cache_status")
        if self.oversight_status not in _OVERSIGHT_STATUSES:
            raise ValueError("invalid oversight_status")
        if self.execution_status not in _EXECUTION_STATUSES:
            raise ValueError("invalid execution_status")
        if self.coverage_status is not None and self.coverage_status not in _COVERAGE_STATUSES:
            raise ValueError("invalid coverage_status")
        if self.parent_span_id is not None and self.span_id is None:
            raise ValueError("parent_span_id requires span_id")
        if isinstance(self.request_count, bool) or not isinstance(self.request_count, int):
            raise TypeError("request_count must be an integer")
        if not 0 <= self.request_count <= _MAX_REQUEST_COUNT:
            raise ValueError(f"request_count must be between 0 and {_MAX_REQUEST_COUNT}")
        if self.latency_ms is not None and (
            isinstance(self.latency_ms, bool)
            or not isinstance(self.latency_ms, (int, float))
            or not math.isfinite(self.latency_ms)
            or self.latency_ms < 0
        ):
            raise ValueError("latency_ms must be finite and non-negative")
        if (self.policy_id is None) != (self.policy_version is None):
            raise ValueError("policy_id and policy_version must be supplied together")
        _validate_rfc3339("observed_at", self.observed_at)
        _validate_rfc3339("execution_observed_at", self.execution_observed_at)
        if self.not_collected != _NOT_COLLECTED:
            raise ValueError("not_collected is fixed by the schema")
        if self.event_kind == "execution_outcome":
            if self.execution_status == "not_observed" or self.execution_observed_at is None:
                raise ValueError("execution outcomes require an observed status and timestamp")
        elif (
            self.execution_status != "not_observed"
            or self.execution_observed_at is not None
            or self.execution_outcome_ref is not None
        ):
            raise ValueError("decision evidence cannot claim an execution outcome")
        if self.error_code is not None and self.evaluation_status != "error":
            raise ValueError("error_code requires evaluation_status=error")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe dictionary without adding or inferring fields."""
        return asdict(self)

    def to_json(self) -> str:
        """Return deterministic compact JSON suitable for a JSONL sink."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> AuditEvidence:
        """Parse an exact schema object, rejecting extensions and mutable reference lists."""
        if not isinstance(value, dict):
            raise TypeError("audit evidence must be a dictionary")
        names = {field.name for field in fields(cls)}
        unknown = set(value) - names
        missing = {
            field.name
            for field in fields(cls)
            if field.default is MISSING and field.default_factory is MISSING
        } - set(value)
        if unknown:
            raise ValueError(f"unknown audit evidence fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"missing audit evidence fields: {', '.join(sorted(missing))}")
        parsed = dict(value)
        for name in (
            "principal_refs",
            "request_refs",
            "action_refs",
            "resource_refs",
            "argument_fingerprints",
            "not_collected",
        ):
            if name in parsed:
                item = parsed[name]
                if not isinstance(item, list):
                    raise TypeError(f"{name} must be a JSON array")
                parsed[name] = tuple(item)
        return cls(**cast(Any, parsed))


_AUDIT_METADATA: ContextVar[AuditMetadata | None] = ContextVar(
    "apparitor_audit_metadata", default=None
)


def current_audit_metadata() -> AuditMetadata | None:
    """Return trusted metadata scoped to the current async context."""
    return _AUDIT_METADATA.get()


@contextmanager
def audit_metadata_scope(metadata: AuditMetadata | None) -> Iterator[None]:
    """Scope trusted metadata; None clears it for the duration of this scope."""
    if metadata is not None and not isinstance(metadata, AuditMetadata):
        raise TypeError("metadata must be AuditMetadata or None")
    token: Token[AuditMetadata | None] = _AUDIT_METADATA.set(metadata)
    try:
        yield
    finally:
        _AUDIT_METADATA.reset(token)


@runtime_checkable
class AuditSink(Protocol):
    """Emit-only boundary for evidence storage managed by the host."""

    def record(self, record: AuditEvidence) -> None: ...


class NoopAuditSink:
    """Default sink for hosts that have not configured evidence storage."""

    def record(self, record: AuditEvidence) -> None:
        del record


class JsonLinesAuditSink:
    """Write one evidence object per line to a host-managed text stream."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def record(self, record: AuditEvidence) -> None:
        self._stream.write(record.to_json() + "\n")


def summarize_evidence(records: list[AuditEvidence]) -> dict[str, object]:
    """Aggregate evidence with explicit, non-overlapping event denominators.

    Duplicate ``evidence_id`` values are counted once and reported.  Authorization and
    execution observations remain separate; this function does not calculate fairness,
    model-performance, legal-compliance, or statutory-incident metrics.
    """
    unique: list[AuditEvidence] = []
    seen: set[str] = set()
    duplicates: set[str] = set()
    for record in records:
        if record.evidence_id in seen:
            duplicates.add(record.evidence_id)
            continue
        seen.add(record.evidence_id)
        unique.append(record)

    event_counts = dict.fromkeys(sorted(_EVENT_KINDS), 0)
    cache_counts = dict.fromkeys(sorted(_CACHE_STATUSES), 0)
    oversight_counts = dict.fromkeys(sorted(_OVERSIGHT_STATUSES), 0)
    execution_counts = dict.fromkeys(sorted(_EXECUTION_STATUSES), 0)
    skipped_records = [
        record
        for record in unique
        if record.event_kind.endswith("decision") and record.verdict == "skip"
    ]
    decision_records = [
        record
        for record in unique
        if record.event_kind.endswith("decision") and record.verdict != "skip"
    ]
    execution_records = [record for record in unique if record.event_kind == "execution_outcome"]
    for record in unique:
        event_counts[record.event_kind] += 1
    for record in decision_records:
        cache_counts[record.cache_status] += 1
        oversight_counts[record.oversight_status] += 1
    for record in execution_records:
        execution_counts[record.execution_status] += 1

    missing = {
        "policy_reference": sum(
            record.policy_id is None or record.policy_version is None for record in decision_records
        ),
        "principal_refs": sum(not record.principal_refs for record in decision_records),
        "request_refs": sum(not record.request_refs for record in decision_records),
    }
    return {
        "schema_version": "apparitor.audit-summary/v1",
        "records_received": len(records),
        "records_unique": len(unique),
        "duplicate_evidence_ids": sorted(duplicates),
        "denominators": {
            "authorization_decisions": len(decision_records),
            "aggregate_decisions": sum(
                record.event_kind == "aggregate_decision" for record in decision_records
            ),
            "per_item_decisions": sum(
                record.event_kind == "per_item_decision" for record in decision_records
            ),
            "skipped_authorizations": len(skipped_records),
            "execution_outcomes": len(execution_records),
            "all_unique_events": len(unique),
        },
        "events": event_counts,
        "decision_outcomes": {
            "policy_denies": sum(
                record.verdict == "block" and record.evaluation_status == "success"
                for record in decision_records
            ),
            "evaluation_faults": sum(
                record.evaluation_status == "error" for record in decision_records
            ),
            "human_review": sum(record.verdict == "human_review" for record in decision_records),
        },
        "authorization_faults": {
            "evaluation_errors": sum(
                record.evaluation_status == "error" for record in decision_records
            ),
            "mapping_failures": event_counts["mapping_failure"],
            "boundary_refusals": event_counts["boundary_refusal"],
            "cancellations": event_counts["cancelled"],
            "total": sum(record.evaluation_status == "error" for record in decision_records)
            + event_counts["mapping_failure"]
            + event_counts["boundary_refusal"]
            + event_counts["cancelled"],
        },
        "cache": cache_counts,
        "execution": {
            "observed": sum(
                record.execution_status != "not_observed" for record in execution_records
            ),
            "unobserved_authorization_decisions": sum(
                record.execution_status == "not_observed" for record in decision_records
            ),
            "statuses": execution_counts,
        },
        "oversight": {
            "pending": oversight_counts["pending"],
            "resolved": oversight_counts["approved"] + oversight_counts["rejected"],
            "statuses": oversight_counts,
        },
        "latency_sample_count": sum(record.latency_ms is not None for record in decision_records),
        "missing_required_metadata": missing,
    }


def make_decision_evidence(
    result: VerdictResult,
    requests: list[EvaluationRequest],
    latency_s: float,
    *,
    metadata: AuditMetadata | None = None,
    event_kind: Literal["aggregate_decision", "per_item_decision"] = "aggregate_decision",
    cache_status: CacheStatus = "unknown",
    error_code: str | None = None,
) -> AuditEvidence:
    """Build decision evidence without copying any AuthZEN request fields."""
    if not math.isfinite(latency_s) or latency_s < 0:
        raise ValueError("latency_s must be finite and non-negative")
    return make_audit_evidence(
        event_kind=event_kind,
        metadata=metadata,
        request_count=len(requests),
        verdict=result.verdict.value,
        evaluation_status=result.status.value,
        latency_ms=round(latency_s * 1000, 3),
        cache_status=cache_status,
        error_code=error_code,
    )


def make_audit_evidence(
    *,
    event_kind: EventKind,
    request_count: int,
    evaluation_status: str,
    metadata: AuditMetadata | None = None,
    verdict: str | None = None,
    latency_ms: float | None = None,
    cache_status: CacheStatus = "unknown",
    error_code: str | None = None,
    argument_fingerprints: tuple[str, ...] | None = None,
    reason_code: str | None = None,
) -> AuditEvidence:
    """Build evidence for decision, mapping-failure, or cancellation paths."""
    trusted = metadata or current_audit_metadata()
    if trusted is None:
        raise ValueError("AuditMetadata is required; no raw-identifier fallback is provided")
    if isinstance(request_count, bool) or not isinstance(request_count, int):
        raise TypeError("request_count must be an integer")
    if not 0 <= request_count <= _MAX_REQUEST_COUNT:
        raise ValueError(f"request_count must be between 0 and {_MAX_REQUEST_COUNT}")
    if latency_ms is not None and (not math.isfinite(latency_ms) or latency_ms < 0):
        raise ValueError("latency_ms must be finite and non-negative")
    _validate_text("evaluation_status", evaluation_status, required=True)
    _validate_text("verdict", verdict)
    _validate_text("error_code", error_code)
    if event_kind not in _EVENT_KINDS:
        raise ValueError("invalid event_kind")
    if cache_status not in _CACHE_STATUSES:
        raise ValueError("invalid cache_status")
    observed = _normalise_time(trusted.observed_at)
    return AuditEvidence(
        schema_version="apparitor.audit/v1",
        event_kind=event_kind,
        evidence_id=f"evd_{uuid.uuid4().hex}",
        event_id=trusted.event_id,
        observed_at=observed.isoformat().replace("+00:00", "Z"),
        tenant_ref=trusted.tenant_ref,
        principal_refs=trusted.principal_refs,
        request_refs=trusted.request_refs,
        request_count=request_count,
        policy_id=trusted.policy_id,
        policy_version=trusted.policy_version,
        correlation_ref=trusted.correlation_ref,
        verdict=verdict,
        evaluation_status=evaluation_status,
        latency_ms=latency_ms,
        cache_status=cache_status,
        oversight_status=trusted.oversight_status,
        error_code=error_code,
        trace_id=trusted.trace_id,
        run_id=trusted.run_id,
        span_id=trusted.span_id,
        parent_span_id=trusted.parent_span_id,
        call_id=trusted.call_id,
        session_ref=trusted.session_ref,
        device_ref=trusted.device_ref,
        user_ref=trusted.user_ref,
        agent_ref=trusted.agent_ref,
        workload_ref=trusted.workload_ref,
        integration=trusted.integration,
        action_refs=trusted.action_refs,
        resource_refs=trusted.resource_refs,
        argument_fingerprints=(
            trusted.argument_fingerprints
            if argument_fingerprints is None
            else argument_fingerprints
        ),
        reason_code=trusted.reason_code if reason_code is None else reason_code,
        coverage_status=trusted.coverage_status,
    )


def with_execution_outcome(
    record: AuditEvidence,
    status: Literal["not_started", "succeeded", "failed", "cancelled"],
    *,
    observed_at: datetime | None = None,
    outcome_ref: str | None = None,
) -> AuditEvidence:
    """Attach a host-observed execution outcome without changing decision evidence."""
    _validate_text("outcome_ref", outcome_ref)
    timestamp = _normalise_time(observed_at).isoformat().replace("+00:00", "Z")
    return replace(
        record,
        event_kind="execution_outcome",
        evidence_id=f"evd_{uuid.uuid4().hex}",
        execution_status=status,
        execution_observed_at=timestamp,
        execution_outcome_ref=outcome_ref,
    )


def make_collection_gap_evidence(
    metadata: AuditMetadata,
    *,
    gap_count: int,
    reason_code: str,
) -> AuditEvidence:
    """Record a bounded host-reported collection gap without asserting its cause."""
    if gap_count < 1:
        raise ValueError("gap_count must be at least 1")
    return make_audit_evidence(
        event_kind="collection_gap",
        request_count=gap_count,
        evaluation_status="not_observed",
        metadata=metadata,
        cache_status="not_applicable",
        reason_code=reason_code,
    )


def argument_fingerprint(
    call: NormalizedToolCall,
    *,
    key: bytes,
    tenant_ref: str,
    max_bytes: int = 4096,
) -> str:
    """Return a tenant-bound keyed digest without retaining tool argument content."""
    if not isinstance(call, NormalizedToolCall):
        raise TypeError("call must be a NormalizedToolCall")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) < 32:
        raise ValueError("key must contain at least 32 bytes")
    _validate_text("tenant_ref", tenant_ref, required=True)
    _validate_text("call.name", call.name, required=True)
    if not isinstance(call.arguments, dict):
        raise TypeError("call.arguments must be a dictionary")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")
    if not 1 <= max_bytes <= _MAX_FINGERPRINT_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {_MAX_FINGERPRINT_BYTES}")
    canonical = {"arguments": call.arguments, "name": call.name, "tenant_ref": tenant_ref}
    try:
        encoded = json.dumps(
            canonical,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("tool call contains unsupported argument values") from exc
    if len(encoded) > max_bytes:
        raise ValueError("canonical tool call exceeds max_bytes")
    return "hmac-sha256:" + hmac.new(key, encoded, hashlib.sha256).hexdigest()
