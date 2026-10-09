"""Tests for typed observation linkage and privacy-preserving fingerprints."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from apparitor.adapters import NormalizedToolCall
from apparitor.audit import (
    AuditEvidence,
    AuditMetadata,
    argument_fingerprint,
    make_audit_evidence,
    make_collection_gap_evidence,
    with_execution_outcome,
)

pytestmark = pytest.mark.unit


def _metadata(**changes: object) -> AuditMetadata:
    values: dict[str, object] = {
        "event_id": "evt_1",
        "tenant_ref": "tenant_opaque",
        "observed_at": datetime(2026, 10, 9, tzinfo=timezone.utc),
        "trace_id": "trace_1",
        "run_id": "run_1",
        "span_id": "span_2",
        "parent_span_id": "span_1",
        "call_id": "call_1",
        "session_ref": "session_opaque",
        "device_ref": "device_opaque",
        "user_ref": "user_opaque",
        "agent_ref": "agent_opaque",
        "workload_ref": "workload_opaque",
        "integration": "litellm",
        "action_refs": ("action_opaque",),
        "resource_refs": ("resource_opaque",),
        "argument_fingerprints": ("hmac-sha256:abc",),
        "reason_code": "policy_denied",
        "coverage_status": "instrumented",
    }
    values.update(changes)
    return AuditMetadata(**values)


def test_metadata_is_preserved_through_execution_linkage() -> None:
    record = make_audit_evidence(
        event_kind="aggregate_decision",
        request_count=1,
        evaluation_status="success",
        metadata=_metadata(),
        argument_fingerprints=("hmac-sha256:override",),
        reason_code="host_override",
    )
    executed = with_execution_outcome(
        record,
        "succeeded",
        observed_at=datetime(2026, 10, 9, 0, 1, tzinfo=timezone.utc),
    )

    assert executed.trace_id == "trace_1"
    assert executed.parent_span_id == "span_1"
    assert executed.session_ref == "session_opaque"
    assert executed.argument_fingerprints == ("hmac-sha256:override",)
    assert executed.reason_code == "host_override"
    assert executed.coverage_status == "instrumented"


def test_span_parent_and_runtime_enums_are_validated() -> None:
    with pytest.raises(ValueError, match="parent_span_id requires span_id"):
        _metadata(span_id=None)
    with pytest.raises(ValueError, match="coverage_status"):
        _metadata(coverage_status="complete")


def test_from_dict_round_trips_json_arrays_and_rejects_unknown_keys() -> None:
    record = make_audit_evidence(
        event_kind="aggregate_decision",
        request_count=1,
        evaluation_status="success",
        metadata=_metadata(),
    )
    payload = record.to_dict()
    for name in (
        "principal_refs",
        "request_refs",
        "action_refs",
        "resource_refs",
        "argument_fingerprints",
        "not_collected",
    ):
        payload[name] = list(payload[name])
    assert AuditEvidence.from_dict(payload) == record

    payload["unexpected"] = "value"
    with pytest.raises(ValueError, match="unknown audit evidence fields"):
        AuditEvidence.from_dict(payload)


def test_from_dict_rejects_wrong_runtime_types_and_collection_claims() -> None:
    record = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        evaluation_status="error",
        metadata=_metadata(),
    )
    payload = json.loads(record.to_json())
    payload["principal_refs"] = "not-an-array"
    with pytest.raises(TypeError, match="JSON array"):
        AuditEvidence.from_dict(payload)

    payload = json.loads(record.to_json())
    payload["not_collected"] = []
    with pytest.raises(ValueError, match="fixed by the schema"):
        AuditEvidence.from_dict(payload)

    payload = json.loads(record.to_json())
    payload["observed_at"] = "2026-10-09T01:00:00+01:00"
    with pytest.raises(ValueError, match="must be UTC"):
        AuditEvidence.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "1", "schema_version"),
        ("verdict", "deny", "verdict"),
        ("evaluation_status", "complete", "evaluation_status"),
    ],
)
def test_from_dict_rejects_unknown_wire_vocabulary(field: str, value: str, message: str) -> None:
    record = make_audit_evidence(
        event_kind="aggregate_decision",
        request_count=1,
        evaluation_status="success",
        verdict="allow",
        metadata=_metadata(),
    )
    payload = json.loads(record.to_json())
    payload[field] = value
    with pytest.raises(ValueError, match=message):
        AuditEvidence.from_dict(payload)


@pytest.mark.parametrize(
    ("verdict", "status"),
    [("skip", "success"), ("allow", "skipped")],
)
def test_skip_verdict_and_status_must_be_paired(verdict: str, status: str) -> None:
    with pytest.raises(ValueError, match="skip verdict"):
        make_audit_evidence(
            event_kind="aggregate_decision",
            request_count=0,
            evaluation_status=status,
            verdict=verdict,
            metadata=_metadata(),
        )


def test_argument_fingerprint_is_canonical_keyed_and_tenant_bound() -> None:
    key = b"k" * 32
    first = NormalizedToolCall(name="send", arguments={"b": 2, "a": "one"})
    reordered = NormalizedToolCall(name="send", arguments={"a": "one", "b": 2})
    changed = NormalizedToolCall(name="send", arguments={"a": "two", "b": 2})

    digest = argument_fingerprint(first, key=key, tenant_ref="tenant_a")
    assert digest == argument_fingerprint(reordered, key=key, tenant_ref="tenant_a")
    assert digest != argument_fingerprint(changed, key=key, tenant_ref="tenant_a")
    assert digest != argument_fingerprint(first, key=key, tenant_ref="tenant_b")
    assert "one" not in digest


def test_argument_fingerprint_rejects_weak_oversize_and_unsupported_inputs() -> None:
    call = NormalizedToolCall(name="send", arguments={"value": "secret"})
    with pytest.raises(ValueError, match="at least 32"):
        argument_fingerprint(call, key=b"short", tenant_ref="tenant")
    with pytest.raises(ValueError, match="max_bytes"):
        argument_fingerprint(call, key=b"k" * 32, tenant_ref="tenant", max_bytes=10)
    unsupported = NormalizedToolCall(name="send", arguments={"value": object()})
    with pytest.raises(ValueError, match="unsupported"):
        argument_fingerprint(unsupported, key=b"k" * 32, tenant_ref="tenant")


def test_collection_gap_is_bounded_and_explicit() -> None:
    record = make_collection_gap_evidence(_metadata(), gap_count=3, reason_code="sink_unavailable")
    assert record.event_kind == "collection_gap"
    assert record.request_count == 3
    assert record.reason_code == "sink_unavailable"
    assert record.evaluation_status == "not_observed"
    with pytest.raises(ValueError, match="at least 1"):
        make_collection_gap_evidence(_metadata(), gap_count=0, reason_code="sink_unavailable")
