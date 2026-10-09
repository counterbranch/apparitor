"""Tests for privacy-bounded compliance evidence records."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO

import pytest

from apparitor.audit import (
    AuditEvidence,
    AuditMetadata,
    AuditSink,
    JsonLinesAuditSink,
    NoopAuditSink,
    audit_metadata_scope,
    current_audit_metadata,
    make_audit_evidence,
    make_decision_evidence,
    summarize_evidence,
    with_execution_outcome,
)
from apparitor.decision import Verdict, VerdictResult, VerdictStatus
from apparitor.models import Action, EvaluationRequest, Resource, Subject

pytestmark = pytest.mark.unit


def _metadata() -> AuditMetadata:
    return AuditMetadata(
        event_id="evt_01",
        tenant_ref="tenant_hmac_a1",
        principal_refs=("principal_hmac_b2",),
        request_refs=("request_hmac_c3",),
        policy_id="access-policy",
        policy_version="sha256:d4",
        correlation_ref="workflow_hmac_e5",
        observed_at=datetime(2026, 10, 9, 12, 30, tzinfo=timezone.utc),
        oversight_status="not_required",
    )


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject(type="user", id="alice@example.test"),
        action=Action(name="tool_call.execute"),
        resource=Resource(
            type="tool", id="mail.send", properties={"recipient": "private@example.test"}
        ),
        context={"protected_attribute": "never-copy-this"},
    )


def test_decision_evidence_uses_only_trusted_opaque_metadata() -> None:
    record = make_decision_evidence(
        VerdictResult(Verdict.BLOCK, "sensitive PDP reason", VerdictStatus.ERROR),
        [_request()],
        0.0123456,
        metadata=_metadata(),
        cache_status="miss",
        error_code="pdp_unavailable",
    )
    payload = record.to_json()

    assert record.request_count == 1
    assert record.verdict == "block"
    assert record.evaluation_status == "error"
    assert record.latency_ms == 12.346
    assert record.execution_status == "not_observed"
    assert record.error_code == "pdp_unavailable"
    for forbidden in (
        "alice@example.test",
        "private@example.test",
        "never-copy-this",
        "sensitive PDP reason",
        "mail.send",
    ):
        assert forbidden not in payload
    assert "protected_attributes" in record.not_collected


def test_context_scope_is_async_context_local_and_resets() -> None:
    with audit_metadata_scope(_metadata()):
        record = make_audit_evidence(
            event_kind="mapping_failure",
            request_count=0,
            evaluation_status="error",
            verdict="block",
        )
    assert record.event_id == "evt_01"
    with pytest.raises(ValueError, match="AuditMetadata is required"):
        make_audit_evidence(event_kind="cancelled", request_count=0, evaluation_status="error")


def test_json_is_deterministic_and_machine_readable() -> None:
    record = make_decision_evidence(
        VerdictResult(Verdict.ALLOW, "allowed", VerdictStatus.SUCCESS),
        [_request()],
        0.001,
        metadata=_metadata(),
        event_kind="per_item_decision",
    )
    payload = record.to_json()
    assert payload == record.to_json()
    parsed = json.loads(payload)
    assert parsed["schema_version"] == "apparitor.audit/v1"
    assert parsed["observed_at"] == "2026-10-09T12:30:00Z"
    assert parsed["request_refs"] == ["request_hmac_c3"]
    assert parsed["evidence_id"].startswith("evd_")


def test_reused_request_metadata_gets_unique_evidence_ids() -> None:
    first = make_audit_evidence(
        event_kind="per_item_decision",
        request_count=1,
        evaluation_status="success",
        metadata=_metadata(),
    )
    second = make_audit_evidence(
        event_kind="per_item_decision",
        request_count=1,
        evaluation_status="success",
        metadata=_metadata(),
    )
    assert first.event_id == second.event_id
    assert first.evidence_id != second.evidence_id


def test_execution_outcome_requires_explicit_host_observation() -> None:
    decision = make_decision_evidence(
        VerdictResult(Verdict.ALLOW, "allowed", VerdictStatus.SUCCESS),
        [_request()],
        0,
        metadata=_metadata(),
    )
    executed = with_execution_outcome(
        decision,
        "succeeded",
        observed_at=datetime(2026, 10, 9, 12, 31, tzinfo=timezone.utc),
        outcome_ref="execution_hmac_f6",
    )
    assert decision.execution_status == "not_observed"
    assert executed.execution_status == "succeeded"
    assert executed.event_kind == "execution_outcome"
    assert executed.evidence_id != decision.evidence_id
    assert executed.execution_observed_at == "2026-10-09T12:31:00Z"


@pytest.mark.parametrize("field", ["event_id", "tenant_ref"])
def test_required_metadata_fields_reject_empty_values(field: str) -> None:
    values = {"event_id": "evt", "tenant_ref": "tenant"}
    values[field] = ""
    with pytest.raises(ValueError, match=field):
        AuditMetadata(**values)


def test_policy_identifier_and_version_are_atomic() -> None:
    with pytest.raises(ValueError, match="supplied together"):
        AuditMetadata(event_id="evt", tenant_ref="tenant", policy_id="policy")


def test_naive_timestamps_and_unbounded_references_are_rejected() -> None:
    with pytest.raises(ValueError, match="timezone"):
        AuditMetadata(event_id="evt", tenant_ref="tenant", observed_at=datetime(2026, 10, 9))
    with pytest.raises(ValueError, match="at most"):
        AuditMetadata(
            event_id="evt",
            tenant_ref="tenant",
            principal_refs=tuple(f"p{i}" for i in range(65)),
        )


def test_sink_protocol_and_noop_sink() -> None:
    sink = NoopAuditSink()
    assert isinstance(sink, AuditSink)
    record = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        evaluation_status="error",
        metadata=_metadata(),
    )
    assert isinstance(record, AuditEvidence)
    sink.record(record)

    stream = StringIO()
    jsonl = JsonLinesAuditSink(stream)
    assert isinstance(jsonl, AuditSink)
    jsonl.record(record)
    assert json.loads(stream.getvalue())["evidence_id"] == record.evidence_id


@pytest.mark.parametrize("latency", [-1.0, float("inf"), float("nan")])
def test_non_finite_or_negative_latency_is_rejected(latency: float) -> None:
    with pytest.raises(ValueError, match="finite and non-negative"):
        make_decision_evidence(
            VerdictResult(Verdict.ALLOW, "allowed", VerdictStatus.SUCCESS),
            [],
            latency,
            metadata=_metadata(),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("event_kind", "invented", "event_kind"),
        ("cache_status", "warm", "cache_status"),
    ],
)
def test_runtime_literals_are_validated(field: str, value: str, message: str) -> None:
    kwargs = {
        "event_kind": "cancelled",
        "request_count": 0,
        "evaluation_status": "error",
        "metadata": _metadata(),
    }
    kwargs[field] = value
    with pytest.raises(ValueError, match=message):
        make_audit_evidence(**kwargs)


def test_reference_containers_must_be_immutable_tuples() -> None:
    with pytest.raises(TypeError, match="tuple"):
        AuditMetadata(event_id="evt", tenant_ref="tenant", principal_refs=["p"])


def test_error_code_requires_error_status() -> None:
    with pytest.raises(ValueError, match="evaluation_status=error"):
        make_audit_evidence(
            event_kind="aggregate_decision",
            request_count=1,
            evaluation_status="success",
            error_code="pdp_error",
            metadata=_metadata(),
        )


def test_direct_record_rejects_invalid_timestamp_and_collection_claim() -> None:
    record = make_audit_evidence(
        event_kind="cancelled",
        request_count=0,
        evaluation_status="error",
        metadata=_metadata(),
    )
    values = record.to_dict()
    values["observed_at"] = "yesterday"
    with pytest.raises(ValueError, match="RFC 3339"):
        AuditEvidence(**values)
    values = record.to_dict()
    values["not_collected"] = ()
    with pytest.raises(ValueError, match="fixed by the schema"):
        AuditEvidence(**values)


def test_summary_separates_denominators_and_deduplicates() -> None:
    allow = make_decision_evidence(
        VerdictResult(Verdict.ALLOW, "allowed", VerdictStatus.SUCCESS),
        [_request()],
        0.01,
        metadata=_metadata(),
        cache_status="hit",
    )
    denied = make_decision_evidence(
        VerdictResult(Verdict.BLOCK, "denied", VerdictStatus.SUCCESS),
        [_request()],
        0.02,
        metadata=_metadata(),
        event_kind="per_item_decision",
        cache_status="not_applicable",
    )
    fault = make_decision_evidence(
        VerdictResult(Verdict.BLOCK, "fault", VerdictStatus.ERROR),
        [_request()],
        0.03,
        metadata=_metadata(),
        error_code="pdp_unavailable",
    )
    outcome = with_execution_outcome(allow, "succeeded")
    summary = summarize_evidence([allow, denied, fault, outcome, denied])

    assert summary["records_received"] == 5
    assert summary["records_unique"] == 4
    assert summary["duplicate_evidence_ids"] == [denied.evidence_id]
    assert summary["denominators"] == {
        "authorization_decisions": 3,
        "aggregate_decisions": 2,
        "per_item_decisions": 1,
        "skipped_authorizations": 0,
        "execution_outcomes": 1,
        "all_unique_events": 4,
    }
    assert summary["decision_outcomes"] == {
        "policy_denies": 1,
        "evaluation_faults": 1,
        "human_review": 0,
    }
    assert summary["cache"] == {
        "hit": 1,
        "miss": 0,
        "not_applicable": 1,
        "unknown": 1,
    }
    assert summary["execution"]["observed"] == 1
    assert summary["execution"]["unobserved_authorization_decisions"] == 3
    assert summary["latency_sample_count"] == 3


def test_summary_reports_oversight_and_missing_linkage_metadata() -> None:
    metadata = AuditMetadata(
        event_id="evt",
        tenant_ref="tenant",
        oversight_status="pending",
    )
    review = make_decision_evidence(
        VerdictResult(Verdict.HUMAN_REVIEW, "review", VerdictStatus.SUCCESS),
        [],
        0,
        metadata=metadata,
    )
    summary = summarize_evidence([review])
    assert summary["decision_outcomes"]["human_review"] == 1
    assert summary["oversight"]["pending"] == 1
    assert summary["oversight"]["resolved"] == 0
    assert summary["missing_required_metadata"] == {
        "policy_reference": 1,
        "principal_refs": 1,
        "request_refs": 1,
    }


def test_pre_evaluation_and_cancelled_faults_have_separate_counts() -> None:
    mapping = make_audit_evidence(
        event_kind="mapping_failure",
        request_count=0,
        evaluation_status="error",
        verdict="block",
        metadata=_metadata(),
    )
    cancelled = make_audit_evidence(
        event_kind="cancelled",
        request_count=1,
        evaluation_status="error",
        verdict="block",
        metadata=_metadata(),
    )
    summary = summarize_evidence([mapping, cancelled, cancelled])
    assert summary["denominators"]["authorization_decisions"] == 0
    assert summary["decision_outcomes"]["policy_denies"] == 0
    assert summary["authorization_faults"] == {
        "evaluation_errors": 0,
        "mapping_failures": 1,
        "boundary_refusals": 0,
        "cancellations": 1,
        "total": 2,
    }
    assert summary["latency_sample_count"] == 0


def test_skipped_observations_do_not_dilute_authorization_denominators() -> None:
    skipped = make_decision_evidence(
        VerdictResult(Verdict.SKIP, "mapper abstained", VerdictStatus.SKIPPED),
        [],
        0,
        metadata=_metadata(),
    )
    summary = summarize_evidence([skipped])
    assert summary["records_unique"] == 1
    assert summary["events"]["aggregate_decision"] == 1
    assert summary["denominators"]["authorization_decisions"] == 0
    assert summary["denominators"]["aggregate_decisions"] == 0
    assert summary["denominators"]["skipped_authorizations"] == 1
    assert summary["latency_sample_count"] == 0


def test_cleared_metadata_scope_restores_outer_context_and_rejects_invalid_type() -> None:
    outer = _metadata()
    with audit_metadata_scope(outer):
        with audit_metadata_scope(None):
            assert current_audit_metadata() is None
        assert current_audit_metadata() is outer
    assert current_audit_metadata() is None
    with (
        pytest.raises(TypeError, match="AuditMetadata or None"),
        audit_metadata_scope(object()),
    ):
        pass
