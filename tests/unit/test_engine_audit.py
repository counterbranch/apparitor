"""Evidence stays separate from authorization and from tool execution."""

from __future__ import annotations

import asyncio

import pytest

from apparitor.adapters import NormalizedToolCall
from apparitor.audit import AuditMetadata, argument_fingerprint, audit_metadata_scope
from apparitor.client import AuthZENClient
from apparitor.decision import Verdict
from apparitor.engine import AuthorizationEngine
from apparitor.errors import AuthZENConfigError
from apparitor.mapping import DualPrincipalMapper
from apparitor.models import Subject

pytestmark = pytest.mark.unit
URL = "http://pdp.test/access/v1/evaluation"
BATCH_URL = "http://pdp.test/access/v1/evaluations"


class Collector:
    def __init__(self):
        self.records = []

    def record(self, record):
        self.records.append(record)


def make_engine(
    make_config,
    noop_sleep,
    sink,
    *,
    audit_fingerprint_key=None,
    audit_integration="core",
    metrics=None,
    review_predicate=None,
    **kwargs,
):
    config = make_config(**kwargs)
    return AuthorizationEngine(
        config,
        client=AuthZENClient(config, sleep=noop_sleep),
        audit_sink=sink,
        audit_fingerprint_key=audit_fingerprint_key,
        audit_integration=audit_integration,
        metrics=metrics,
        review_predicate=review_predicate,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [True, False])
async def test_decisions_do_not_claim_execution(
    make_config, noop_sleep, make_openai_call, respx_mock, allowed
):
    respx_mock.post(URL).respond(json={"decision": allowed})
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink)
    with audit_metadata_scope(
        AuditMetadata("req_1", "ten_1", policy_id="pol_1", policy_version="v1")
    ):
        result = await engine.evaluate_tool_calls([make_openai_call("read", token="secret")])
    record = sink.records[0]
    assert record.verdict == result.verdict.value
    assert record.execution_status == "not_observed"
    assert record.policy_version == "v1"
    assert record.request_count == 1
    assert record.cache_status == "not_applicable"
    assert "secret" not in record.to_json()
    assert "read" not in record.to_json()
    assert engine.audit_failures == 0
    await engine.aclose()


@pytest.mark.asyncio
async def test_real_cache_results(make_config, noop_sleep, make_openai_call, respx_mock):
    route = respx_mock.post(URL).respond(json={"decision": True})
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink, cache_enabled=True)
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1")):
        for _ in range(2):
            await engine.evaluate_tool_calls([make_openai_call("read")])
    assert [r.cache_status for r in sink.records] == ["miss", "hit"]
    assert sink.records[0].evidence_id != sink.records[1].evidence_id
    assert route.call_count == 1
    await engine.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["pdp", "review"])
async def test_cache_miss_is_retained_when_evaluation_fails(
    make_config, noop_sleep, make_openai_call, respx_mock, failure
):
    if failure == "pdp":
        respx_mock.post(URL).respond(status_code=503)
        review_predicate = None
    else:
        respx_mock.post(URL).respond(json={"decision": True, "context": {}})

        def review_predicate(context):
            raise RuntimeError("review failed")

    sink = Collector()
    engine = make_engine(
        make_config,
        noop_sleep,
        sink,
        cache_enabled=True,
        max_retries=0,
        review_predicate=review_predicate,
    )

    with audit_metadata_scope(AuditMetadata("req_error", "ten_1")):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])

    assert result.verdict is Verdict.BLOCK
    assert sink.records[0].evaluation_status == "error"
    assert sink.records[0].cache_status == "miss"
    await engine.aclose()


@pytest.mark.asyncio
async def test_mapping_fault_emits_without_raw_input(make_config, noop_sleep):
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink)
    with audit_metadata_scope(AuditMetadata("req_bad", "ten_1")):
        result = await engine.evaluate_tool_calls([{"malformed": "secret"}])
    assert result.verdict is Verdict.BLOCK
    assert sink.records[0].event_kind == "mapping_failure"
    assert sink.records[0].request_count == 0
    assert "secret" not in sink.records[0].to_json()
    await engine.aclose()


@pytest.mark.asyncio
async def test_audit_failure_and_missing_metadata_preserve_denial(
    make_config, noop_sleep, make_openai_call, respx_mock, caplog
):
    respx_mock.post(URL).respond(json={"decision": False})

    class BrokenSink:
        def record(self, record):
            raise RuntimeError("storage-secret")

    engine = make_engine(make_config, noop_sleep, BrokenSink())
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1")):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.BLOCK
    assert (await engine.evaluate_tool_calls([make_openai_call("read")])).verdict is Verdict.BLOCK
    assert engine.audit_failures == 2
    assert "storage-secret" not in caplog.text
    await engine.aclose()


@pytest.mark.asyncio
async def test_listing_and_dual_principal_counts(make_config, noop_sleep, respx_mock):
    sink = Collector()
    config = make_config(cache_enabled=True)
    engine = AuthorizationEngine(
        config,
        client=AuthZENClient(config, sleep=noop_sleep),
        mapper=DualPrincipalMapper(config, agent_subject=Subject(type="agent", id="boundary")),
        audit_sink=sink,
    )
    respx_mock.post(BATCH_URL).respond(json={"evaluations": [{"decision": True}] * 4})
    with audit_metadata_scope(AuditMetadata("req_list", "ten_1")):
        results = await engine.evaluate_each(
            [
                NormalizedToolCall(name="read", arguments={}),
                NormalizedToolCall(name="write", arguments={}),
            ],
            request_context={"subject": Subject(type="user", id="caller")},
        )
    assert len(results) == 2
    assert [r.request_count for r in sink.records] == [2, 2]
    assert all(r.event_kind == "per_item_decision" for r in sink.records)
    assert all(r.cache_status == "not_applicable" for r in sink.records)
    await engine.aclose()


@pytest.mark.asyncio
async def test_cancellation_has_evidence_and_propagates(
    make_config, noop_sleep, make_openai_call, respx_mock
):
    async def cancel(request):
        raise asyncio.CancelledError

    respx_mock.post(URL).mock(side_effect=cancel)
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink, cache_enabled=True)
    with (
        audit_metadata_scope(AuditMetadata("req_cancel", "ten_1")),
        pytest.raises(asyncio.CancelledError),
    ):
        await engine.evaluate_tool_calls([make_openai_call("read")])
    assert sink.records[0].event_kind == "cancelled"
    assert sink.records[0].verdict == "block"
    assert sink.records[0].request_count == 1
    assert sink.records[0].cache_status == "miss"
    await engine.aclose()


@pytest.mark.asyncio
async def test_batch_cancellation_cache_is_not_applicable(make_config, noop_sleep, respx_mock):
    async def cancel(request):
        raise asyncio.CancelledError

    respx_mock.post(BATCH_URL).mock(side_effect=cancel)
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink, cache_enabled=True)
    calls = [NormalizedToolCall(name="read"), NormalizedToolCall(name="write")]
    with (
        audit_metadata_scope(AuditMetadata("req_cancel", "ten_1")),
        pytest.raises(asyncio.CancelledError),
    ):
        await engine.evaluate_normalized(calls, {"subject": Subject(type="user", id="caller")})
    assert sink.records[0].event_kind == "cancelled"
    assert sink.records[0].cache_status == "not_applicable"
    await engine.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [True, False])
async def test_synchronous_sink_cancellation_does_not_replace_verdict(
    make_config, noop_sleep, make_openai_call, respx_mock, allowed
):
    respx_mock.post(URL).respond(json={"decision": allowed})

    class CancellingSink:
        def record(self, record):
            raise asyncio.CancelledError

    engine = make_engine(make_config, noop_sleep, CancellingSink())
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1")):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is (Verdict.ALLOW if allowed else Verdict.BLOCK)
    assert engine.audit_failures == 1
    await engine.aclose()


@pytest.mark.asyncio
async def test_original_pdp_cancellation_survives_cancelling_sink(
    make_config, noop_sleep, make_openai_call, respx_mock
):
    cancellation = asyncio.CancelledError("pdp cancellation")

    async def cancel(request):
        raise cancellation

    class CancellingSink:
        def record(self, record):
            raise asyncio.CancelledError("sink cancellation")

    respx_mock.post(URL).mock(side_effect=cancel)
    engine = make_engine(make_config, noop_sleep, CancellingSink(), cache_enabled=True)
    with (
        audit_metadata_scope(AuditMetadata("req_cancel", "ten_1")),
        pytest.raises(asyncio.CancelledError) as raised,
    ):
        await engine.evaluate_tool_calls([make_openai_call("read")])
    assert raised.value is cancellation
    assert engine.audit_failures == 1
    await engine.aclose()


@pytest.mark.asyncio
async def test_synchronous_metrics_cancellation_does_not_replace_verdict(
    make_config, noop_sleep, make_openai_call, respx_mock
):
    respx_mock.post(URL).respond(json={"decision": True})

    class CancellingMetrics:
        def record_decision(self, *, verdict, status, latency_s):
            raise asyncio.CancelledError

        def record_cache(self, *, hit):
            raise asyncio.CancelledError

    sink = Collector()
    engine = make_engine(
        make_config,
        noop_sleep,
        sink,
        cache_enabled=True,
        metrics=CancellingMetrics(),
    )
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1")):
        result = await engine.evaluate_tool_calls([make_openai_call("read")])
    assert result.verdict is Verdict.ALLOW
    assert sink.records[0].cache_status == "miss"
    await engine.aclose()


@pytest.mark.asyncio
async def test_pre_engine_refusal_is_counted(make_config, noop_sleep):
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink)
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1", reason_code="untrusted-host-reason")):
        engine.record_refusal()
    assert engine.metrics.decisions[("block", "error")] == 1
    assert sink.records[0].event_kind == "boundary_refusal"
    assert sink.records[0].reason_code == "boundary_refused"
    await engine.aclose()


@pytest.mark.asyncio
async def test_pre_engine_refusal_accepts_bounded_adapter_reason(make_config, noop_sleep):
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink)
    with audit_metadata_scope(AuditMetadata("req_1", "ten_1")):
        engine.record_refusal("subject_boundary_collapsed")
    assert sink.records[0].event_kind == "boundary_refusal"
    assert sink.records[0].reason_code == "subject_boundary_collapsed"
    await engine.aclose()


@pytest.mark.asyncio
async def test_argument_fingerprints_distinguish_values_and_tenants(
    make_config, noop_sleep, respx_mock
):
    respx_mock.post(URL).respond(json={"decision": True})
    sink = Collector()
    engine = make_engine(
        make_config, noop_sleep, sink, audit_fingerprint_key=b"fingerprint-key" * 3
    )

    for tenant, value in (
        ("tenant_a", "first-private-value"),
        ("tenant_a", "second-private-value"),
        ("tenant_b", "first-private-value"),
    ):
        with audit_metadata_scope(AuditMetadata("req_1", tenant)):
            await engine.evaluate_normalized(
                [NormalizedToolCall(name="lookup", arguments={"query": value})],
                {"subject": Subject(type="user", id="caller")},
            )

    fingerprints = [record.argument_fingerprints[0] for record in sink.records]
    assert len(set(fingerprints)) == 3
    assert all(value.startswith("hmac-sha256:") for value in fingerprints)
    payload = "".join(record.to_json() for record in sink.records)
    assert "first-private-value" not in payload
    assert "second-private-value" not in payload
    await engine.aclose()


@pytest.mark.asyncio
async def test_per_item_records_receive_their_corresponding_fingerprint(
    make_config, noop_sleep, respx_mock
):
    respx_mock.post(BATCH_URL).respond(
        json={"evaluations": [{"decision": True}, {"decision": False}]}
    )
    sink = Collector()
    key = b"fingerprint-key" * 3
    engine = make_engine(make_config, noop_sleep, sink, audit_fingerprint_key=key)
    calls = [
        NormalizedToolCall(name="lookup", arguments={"query": "private-first"}),
        NormalizedToolCall(name="lookup", arguments={"query": "private-second"}),
    ]

    with audit_metadata_scope(AuditMetadata("req_list", "tenant_a")):
        results = await engine.evaluate_each(
            calls, request_context={"subject": Subject(type="user", id="caller")}
        )

    assert [result.verdict for result in results] == [Verdict.ALLOW, Verdict.BLOCK]
    assert [record.argument_fingerprints for record in sink.records] == [
        (argument_fingerprint(call, key=key, tenant_ref="tenant_a"),) for call in calls
    ]
    assert all(record.event_kind == "per_item_decision" for record in sink.records)
    payload = "".join(record.to_json() for record in sink.records)
    assert "private-first" not in payload
    assert "private-second" not in payload
    await engine.aclose()


@pytest.mark.asyncio
async def test_aggregate_over_reference_limit_suppresses_fingerprints_only(
    make_config, noop_sleep, respx_mock
):
    calls = [NormalizedToolCall(name=f"tool_{index}") for index in range(65)]
    respx_mock.post(BATCH_URL).respond(json={"evaluations": [{"decision": True} for _ in calls]})
    sink = Collector()
    engine = make_engine(
        make_config, noop_sleep, sink, audit_fingerprint_key=b"fingerprint-key" * 3
    )

    with audit_metadata_scope(AuditMetadata("req_many", "tenant_a")):
        result = await engine.evaluate_normalized(
            calls, {"subject": Subject(type="user", id="caller")}
        )

    assert result.verdict is Verdict.ALLOW
    assert len(sink.records) == 1
    assert sink.records[0].verdict == "allow"
    assert sink.records[0].request_count == 65
    assert sink.records[0].argument_fingerprints == ()
    assert engine.audit_failures == 0
    assert engine.audit_fingerprint_failures == 1
    payload = sink.records[0].to_json()
    assert all(call.name not in payload for call in calls)
    await engine.aclose()


@pytest.mark.asyncio
async def test_oversize_fingerprint_is_suppressed_without_affecting_decision(
    make_config, noop_sleep, respx_mock, caplog
):
    respx_mock.post(URL).respond(json={"decision": False})
    sink = Collector()
    engine = make_engine(
        make_config,
        noop_sleep,
        sink,
        audit_fingerprint_key=b"fingerprint-key" * 3,
        max_argument_bytes=32,
    )
    raw_value = "private-oversize-value" * 10

    with audit_metadata_scope(AuditMetadata("req_1", "tenant_a")):
        result = await engine.evaluate_normalized(
            [NormalizedToolCall(name="lookup", arguments={"query": raw_value})],
            {"subject": Subject(type="user", id="caller")},
        )

    assert result.verdict is Verdict.BLOCK
    assert engine.audit_fingerprint_failures == 1
    assert engine.audit_failures == 0
    assert sink.records[0].argument_fingerprints == ()
    assert raw_value not in sink.records[0].to_json()
    assert raw_value not in caplog.text
    await engine.aclose()


@pytest.mark.asyncio
async def test_engine_derives_reason_code_and_integration_label(
    make_config, noop_sleep, respx_mock
):
    respx_mock.post(URL).respond(json={"decision": False})
    sink = Collector()
    engine = make_engine(make_config, noop_sleep, sink, audit_integration="litellm")

    with audit_metadata_scope(
        AuditMetadata(
            "req_1",
            "tenant_a",
            integration="untrusted-host-label",
            reason_code="untrusted-host-reason",
        )
    ):
        await engine.evaluate_normalized(
            [NormalizedToolCall(name="lookup")],
            {"subject": Subject(type="user", id="caller")},
        )

    assert sink.records[0].integration == "litellm"
    assert sink.records[0].reason_code == "policy_denied"
    await engine.aclose()


@pytest.mark.parametrize("key", [b"short", "not-bytes"])
def test_invalid_audit_fingerprint_key_is_rejected(make_config, noop_sleep, key):
    with pytest.raises(AuthZENConfigError, match="at least 32 bytes"):
        make_engine(make_config, noop_sleep, Collector(), audit_fingerprint_key=key)
