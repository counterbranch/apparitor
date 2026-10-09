from __future__ import annotations

import asyncio
from typing import Any

import pytest
import respx

pytest.importorskip("litellm")

from litellm.exceptions import GuardrailRaisedException
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.llms.openai import ResponsesAPIResponse
from litellm.types.rerank import RerankResponse
from litellm.types.utils import (
    EmbeddingResponse,
    ImageResponse,
    ModelResponse,
    TextCompletionResponse,
    TranscriptionResponse,
)

from apparitor.adapters import NormalizedToolCall
from apparitor.audit import AuditEvidence, AuditMetadata, argument_fingerprint, audit_metadata_scope
from apparitor.decision import Verdict, VerdictResult, VerdictStatus
from apparitor.errors import AuthZENConfigError
from apparitor.litellm import LiteLLMAuthorizationGuardrail


class RecordingEngine:
    def __init__(self, verdict: VerdictResult) -> None:
        self.verdict = verdict
        self.calls: list[tuple[object, dict[str, object]]] = []
        self.closed = False
        self.refusals = 0

    async def evaluate_normalized(self, calls: object, context: dict[str, object]) -> VerdictResult:
        self.calls.append((calls, context))
        return self.verdict

    async def evaluate_tool_calls(self, calls: object, context: dict[str, object]) -> VerdictResult:
        self.calls.append((calls, context))
        return self.verdict

    async def aclose(self) -> None:
        self.closed = True

    def record_refusal(self) -> None:
        self.refusals += 1


class AuditCollector:
    def __init__(self) -> None:
        self.records: list[AuditEvidence] = []

    def record(self, record: AuditEvidence) -> None:
        self.records.append(record)


def _guardrail(
    verdict: Verdict = Verdict.ALLOW,
    *,
    authorize_offered_tools: bool = True,
) -> tuple[LiteLLMAuthorizationGuardrail, RecordingEngine]:
    guardrail = LiteLLMAuthorizationGuardrail(
        "https://pdp.example.com", default_on=True, authorize_offered_tools=authorize_offered_tools
    )
    engine = RecordingEngine(VerdictResult(verdict, "test", VerdictStatus.SUCCESS))
    guardrail._engine = engine  # type: ignore[assignment]
    return guardrail, engine


def _auth(user_id: str | None = "trusted-user") -> UserAPIKeyAuth:
    return UserAPIKeyAuth(user_id=user_id)


@pytest.mark.asyncio
async def test_pre_call_authorizes_every_offered_tool_as_authenticated_user() -> None:
    guardrail, engine = _guardrail()
    data = {
        "metadata": {"user_id": "attacker"},
        "user": "attacker",
        "tools": [
            {"type": "function", "function": {"name": "read_file"}},
            {"type": "function", "name": "shell"},
        ],
    }

    returned = await guardrail.async_pre_call_hook(_auth(), object(), data, "completion")  # type: ignore[arg-type]

    assert returned is data
    calls, context = engine.calls[0]
    assert [call.name for call in calls] == ["read_file", "shell"]  # type: ignore[union-attr]
    assert context["subject"].id == "trusted-user"  # type: ignore[union-attr]
    assert context["user_id"] == "trusted-user"


@pytest.mark.asyncio
async def test_missing_authenticated_identity_fails_closed() -> None:
    guardrail, engine = _guardrail()

    with pytest.raises(GuardrailRaisedException, match="no authorization subject"):
        await guardrail.async_pre_call_hook(
            _auth(None),
            object(),  # type: ignore[arg-type]
            {"metadata": {"user_id": "untrusted"}, "tools": [{"name": "shell"}]},
            "completion",  # type: ignore[arg-type]
        )
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_post_call_authorizes_exact_arguments_from_all_choices() -> None:
    guardrail, engine = _guardrail()
    response = ModelResponse(
        choices=[
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "one",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": '{"path":"/tmp/x"}'},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            },
            {
                "index": 1,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "two",
                            "type": "function",
                            "function": {"name": "delete_file", "arguments": '{"path":"/etc/x"}'},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            },
        ]
    )

    returned = await guardrail.async_post_call_success_hook({}, _auth(), response)

    assert returned is response
    calls, _ = engine.calls[0]
    assert [call["function"]["name"] for call in calls] == ["read_file", "delete_file"]  # type: ignore[index]


@pytest.mark.asyncio
async def test_post_call_policy_deny_raises_guardrail_block() -> None:
    guardrail, _ = _guardrail(Verdict.BLOCK)
    response = ModelResponse(
        choices=[
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "one",
                            "type": "function",
                            "function": {"name": "delete_file", "arguments": "{}"},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    )

    with pytest.raises(GuardrailRaisedException) as caught:
        await guardrail.async_post_call_success_hook({}, _auth(), response)
    assert caught.value.status_code == 403
    assert caught.value.blocked_content is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        EmbeddingResponse(model="embedding-model", data=[]),
        ImageResponse(created=1, data=[]),
        TextCompletionResponse(choices=[]),
        TranscriptionResponse(text="hello"),
        RerankResponse(results=[]),
    ],
)
async def test_default_on_passes_explicit_non_executable_response_families(
    response: object,
) -> None:
    guardrail, engine = _guardrail()

    returned = await guardrail.async_post_call_success_hook({}, _auth(), response)  # type: ignore[arg-type]

    assert returned is response
    assert engine.calls == []


def _responses_function_call(arguments: str = '{"path":"/tmp/x"}') -> ResponsesAPIResponse:
    return ResponsesAPIResponse(
        id="resp_1",
        created_at=1,
        model="test",
        object="response",
        output=[
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_1",
                "name": "read_file",
                "arguments": arguments,
                "status": "completed",
            }
        ],
        status="completed",
    )


@pytest.mark.asyncio
async def test_responses_api_function_call_authorizes_exact_arguments() -> None:
    guardrail, engine = _guardrail()
    response = _responses_function_call('{"path":"/etc/passwd"}')

    await guardrail.async_post_call_success_hook({}, _auth(), response)

    calls, _ = engine.calls[0]
    assert calls == [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "read_file", "arguments": '{"path":"/etc/passwd"}'},
        }
    ]


@pytest.mark.asyncio
async def test_responses_api_function_call_deny_blocks() -> None:
    guardrail, _ = _guardrail(Verdict.BLOCK)

    with pytest.raises(GuardrailRaisedException, match="not authorized"):
        await guardrail.async_post_call_success_hook({}, _auth(), _responses_function_call())


@pytest.mark.asyncio
async def test_anthropic_tool_use_authorizes_exact_input() -> None:
    guardrail, engine = _guardrail()
    response = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "checking"},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "read_file",
                "input": {"path": "/etc/passwd"},
            },
        ],
        "stop_reason": "tool_use",
    }

    await guardrail.async_post_call_success_hook({}, _auth(), response)  # type: ignore[arg-type]

    calls, _ = engine.calls[0]
    assert calls == [
        {
            "type": "tool_use",
            "id": "toolu_1",
            "name": "read_file",
            "input": {"path": "/etc/passwd"},
        }
    ]


@pytest.mark.asyncio
async def test_responses_api_unsupported_executable_type_fails_closed() -> None:
    guardrail, engine = _guardrail()
    response = ResponsesAPIResponse(
        id="resp_1",
        created_at=1,
        model="test",
        object="response",
        output=[
            {
                "type": "computer_call",
                "id": "computer_1",
                "call_id": "call_1",
                "action": {"type": "screenshot"},
                "pending_safety_checks": [],
                "status": "completed",
            }
        ],
        status="completed",
    )

    with pytest.raises(GuardrailRaisedException, match="could not be verified"):
        await guardrail.async_post_call_success_hook({}, _auth(), response)
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_streaming_is_refused_before_any_chunk_is_consumed() -> None:
    guardrail, engine = _guardrail()
    consumed = False

    async def chunks() -> Any:
        nonlocal consumed
        consumed = True
        yield object()

    with pytest.raises(GuardrailRaisedException, match="streaming is unsupported"):
        async for _ in guardrail.async_post_call_streaming_iterator_hook(_auth(), chunks(), {}):
            pass
    assert consumed is False
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_pre_call_refuses_streaming_before_provider_call() -> None:
    guardrail, engine = _guardrail()

    with pytest.raises(GuardrailRaisedException, match="streaming is unsupported"):
        await guardrail.async_pre_call_hook(
            _auth(),
            object(),
            {"stream": True},
            "completion",  # type: ignore[arg-type]
        )
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_pre_call_refuses_background_response() -> None:
    guardrail, engine = _guardrail()

    with pytest.raises(GuardrailRaisedException, match="background responses are unsupported"):
        await guardrail.async_pre_call_hook(
            _auth(),
            object(),
            {"background": True},
            "responses",  # type: ignore[arg-type]
        )
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_close_delegates_to_engine() -> None:
    guardrail, engine = _guardrail()
    await guardrail.aclose()
    assert engine.closed


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    guardrail, engine = _guardrail()

    async def cancelled(calls: object, context: dict[str, object]) -> VerdictResult:
        raise asyncio.CancelledError

    engine.evaluate_tool_calls = cancelled  # type: ignore[method-assign]
    response = ModelResponse(
        choices=[
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "one",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": "{}"},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    )

    with pytest.raises(asyncio.CancelledError):
        await guardrail.async_post_call_success_hook({}, _auth(), response)
    assert engine.refusals == 0


def test_audit_sink_requires_trusted_metadata_resolver_before_backend_build() -> None:
    with pytest.raises(AuthZENConfigError, match="audit_metadata_resolver is required"):
        LiteLLMAuthorizationGuardrail("not a valid URL", audit_sink=AuditCollector())


def _audit_metadata(auth: UserAPIKeyAuth) -> AuditMetadata:
    identity = auth.user_id or "authenticated-key-without-user"
    return AuditMetadata(
        event_id=f"event-{identity}",
        tenant_ref=f"tenant-{identity}",
        principal_refs=(f"principal-{identity}",),
    )


@pytest.mark.asyncio
async def test_real_engine_records_trusted_litellm_evidence_and_exact_arguments(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("https://pdp.example.com/access/v1/evaluation").respond(json={"decision": True})
    sink = AuditCollector()
    key = b"litellm-fingerprint-key-32-bytes!!"
    guardrail = LiteLLMAuthorizationGuardrail(
        "https://pdp.example.com",
        audit_sink=sink,
        audit_fingerprint_key=key,
        audit_metadata_resolver=_audit_metadata,
    )
    response = _responses_function_call('{"path":"/private/exact"}')

    await guardrail.async_post_call_success_hook({}, _auth("alice"), response)

    assert len(sink.records) == 1
    record = sink.records[0]
    assert record.tenant_ref == "tenant-alice"
    assert record.principal_refs == ("principal-alice",)
    assert record.integration == "litellm"
    assert record.verdict == "allow"
    assert record.argument_fingerprints == (
        argument_fingerprint(
            NormalizedToolCall(name="read_file", arguments={"path": "/private/exact"}, id="call_1"),
            key=key,
            tenant_ref="tenant-alice",
        ),
    )
    assert guardrail._engine.audit_failures == 0
    assert "/private/exact" not in record.to_json()
    await guardrail.aclose()


@pytest.mark.asyncio
async def test_real_engine_records_denial_and_boundary_refusals(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("https://pdp.example.com/access/v1/evaluation").respond(
        json={"decision": False}
    )
    sink = AuditCollector()
    guardrail = LiteLLMAuthorizationGuardrail(
        "https://pdp.example.com",
        audit_sink=sink,
        audit_metadata_resolver=_audit_metadata,
    )

    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_post_call_success_hook({}, _auth("alice"), _responses_function_call())
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_pre_call_hook(
            _auth(None),
            object(),
            {"tools": [{"name": "read_file"}]},
            "completion",  # type: ignore[arg-type]
        )
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_pre_call_hook(
            _auth("alice"),
            object(),
            {"stream": True},
            "completion",  # type: ignore[arg-type]
        )

    assert [record.verdict for record in sink.records] == ["block", "block", "block"]
    assert [record.tenant_ref for record in sink.records] == [
        "tenant-alice",
        "tenant-authenticated-key-without-user",
        "tenant-alice",
    ]
    assert guardrail._engine.audit_failures == 0
    await guardrail.aclose()


@pytest.mark.asyncio
async def test_concurrent_authenticated_audit_scopes_do_not_leak(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("https://pdp.example.com/access/v1/evaluation").respond(json={"decision": True})
    sink = AuditCollector()
    guardrail = LiteLLMAuthorizationGuardrail(
        "https://pdp.example.com",
        audit_sink=sink,
        audit_metadata_resolver=_audit_metadata,
    )

    await asyncio.gather(
        guardrail.async_post_call_success_hook({}, _auth("alice"), _responses_function_call()),
        guardrail.async_post_call_success_hook({}, _auth("bob"), _responses_function_call()),
    )

    assert {(record.tenant_ref, record.principal_refs) for record in sink.records} == {
        ("tenant-alice", ("principal-alice",)),
        ("tenant-bob", ("principal-bob",)),
    }
    await guardrail.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("resolver_error", [RuntimeError, asyncio.CancelledError])
@pytest.mark.parametrize("allowed", [True, False])
async def test_audit_resolver_failure_does_not_change_authorization(
    respx_mock: respx.MockRouter,
    resolver_error: type[BaseException],
    allowed: bool,
) -> None:
    respx_mock.post("https://pdp.example.com/access/v1/evaluation").respond(
        json={"decision": allowed}
    )
    sink = AuditCollector()

    def broken_resolver(auth: UserAPIKeyAuth) -> AuditMetadata:
        raise resolver_error(f"private resolver detail for {auth.user_id}")

    guardrail = LiteLLMAuthorizationGuardrail(
        "https://pdp.example.com",
        audit_sink=sink,
        audit_metadata_resolver=broken_resolver,
    )

    with audit_metadata_scope(AuditMetadata(event_id="outer", tenant_ref="outer-tenant")):
        if allowed:
            returned = await guardrail.async_post_call_success_hook(
                {}, _auth("alice"), _responses_function_call()
            )
            assert isinstance(returned, ResponsesAPIResponse)
        else:
            with pytest.raises(GuardrailRaisedException) as exc:
                await guardrail.async_post_call_success_hook(
                    {}, _auth("alice"), _responses_function_call()
                )
            assert exc.value.status_code == 403
    assert sink.records == []
    assert guardrail._engine.audit_failures == 1
    await guardrail.aclose()


@pytest.mark.parametrize("block_type", ["server_tool_use", "mcp_tool_use", "unknown_future_call"])
@pytest.mark.asyncio
async def test_unknown_anthropic_executable_blocks_refuse(block_type: str) -> None:
    guardrail, engine = _guardrail()
    response = {
        "type": "message",
        "content": [{"type": block_type, "name": "read_file", "input": {}}],
    }
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_post_call_success_hook({}, _auth(), response)
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.parametrize("tool_type", ["custom", "mcp", "web_search_20250305", "computer_use"])
@pytest.mark.parametrize("authorize_offered", [True, False])
@pytest.mark.asyncio
async def test_unsupported_provider_tools_refuse_before_provider(
    tool_type: str, authorize_offered: bool
) -> None:
    guardrail, engine = _guardrail(authorize_offered_tools=authorize_offered)
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_pre_call_hook(
            _auth(), object(), {"tools": [{"type": tool_type, "name": "shell"}]}, "completion"
        )
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_disabling_declaration_policy_check_still_authorizes_returned_calls() -> None:
    guardrail, engine = _guardrail(Verdict.BLOCK, authorize_offered_tools=False)
    data = {"tools": [{"type": "function", "function": {"name": "read_file"}}]}
    returned = await guardrail.async_pre_call_hook(_auth(), object(), data, "completion")
    assert returned is data
    assert engine.calls == []
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_post_call_success_hook({}, _auth(), _responses_function_call())
    assert len(engine.calls) == 1


@pytest.mark.parametrize("authorize_offered", [True, False])
@pytest.mark.parametrize(
    ("provider_fields", "call_type"),
    [
        (
            {"mcp_servers": [{"type": "url", "url": "https://mcp.example.test", "name": "mcp"}]},
            "anthropic_messages",
        ),
        ({"web_search_options": {}}, "completion"),
        ({"mcp_servers": []}, "anthropic_messages"),
    ],
)
@pytest.mark.asyncio
async def test_provider_execution_fields_refuse_without_tool_declarations(
    provider_fields: dict[str, Any], call_type: str, authorize_offered: bool
) -> None:
    guardrail, engine = _guardrail(authorize_offered_tools=authorize_offered)
    with pytest.raises(GuardrailRaisedException, match="provider-executed tools"):
        await guardrail.async_pre_call_hook(_auth(), object(), provider_fields, call_type)
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_null_provider_execution_fields_do_not_enable_execution() -> None:
    guardrail, engine = _guardrail()
    data = {"mcp_servers": None, "web_search_options": None}
    assert await guardrail.async_pre_call_hook(_auth(), object(), data, "completion") is data
    assert engine.calls == []
    assert engine.refusals == 0


@pytest.mark.asyncio
async def test_anthropic_custom_typed_client_tool_is_authorized() -> None:
    guardrail, engine = _guardrail()
    data = {
        "tools": [
            {
                "type": "custom",
                "name": "read_file",
                "input_schema": {"type": "object", "properties": {}},
            }
        ]
    }

    returned = await guardrail.async_pre_call_hook(
        _auth(),
        object(),
        data,
        "anthropic_messages",  # type: ignore[arg-type]
    )

    assert returned is data
    calls, _ = engine.calls[0]
    assert [call.name for call in calls] == ["read_file"]  # type: ignore[union-attr]


@pytest.mark.parametrize("hooks", [["pre_call"], ["post_call"], []])
def test_required_hooks_cannot_be_disabled(hooks: list[str]) -> None:
    from apparitor.errors import AuthZENConfigError

    with pytest.raises(AuthZENConfigError, match="requires pre_call and post_call"):
        LiteLLMAuthorizationGuardrail("https://pdp.example.com", event_hook=hooks)


@pytest.mark.asyncio
async def test_guardrail_does_not_copy_raw_response_into_logging_metadata(caplog) -> None:
    guardrail, _ = _guardrail()
    secret = "PRIVATE_TOOL_ARGUMENT_SENTINEL"
    response = ModelResponse(
        choices=[
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": secret,
                    "tool_calls": [
                        {
                            "id": "one",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": '{"token":"' + secret + '"}',
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    )
    data = {"metadata": {}}
    with caplog.at_level("DEBUG"):
        returned = await guardrail.async_post_call_success_hook(data, _auth(), response)
    assert returned is response
    assert data == {"metadata": {}}
    assert secret not in caplog.text


@pytest.mark.parametrize("call_type", ["send_message", "asend_message"])
@pytest.mark.asyncio
async def test_a2a_proxy_invocation_is_refused_before_agent_execution(call_type: str) -> None:
    guardrail, engine = _guardrail()
    with pytest.raises(GuardrailRaisedException, match="A2A proxy routes require"):
        await guardrail.async_pre_call_hook(_auth(), object(), {}, call_type)
    assert engine.calls == []
    assert engine.refusals == 1


@pytest.mark.asyncio
async def test_a2a_response_cannot_bypass_pre_call_refusal() -> None:
    from litellm.types.agents import LiteLLMSendMessageResponse

    guardrail, engine = _guardrail()
    response = LiteLLMSendMessageResponse.from_dict(
        {
            "id": "request",
            "jsonrpc": "2.0",
            "result": {
                "kind": "message",
                "messageId": "one",
                "role": "agent",
                "parts": [{"kind": "text", "text": "hello"}],
            },
        }
    )
    with pytest.raises(GuardrailRaisedException):
        await guardrail.async_post_call_success_hook({}, _auth(), response)
    assert engine.calls == []
    assert engine.refusals == 1
