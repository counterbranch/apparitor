"""LiteLLM Proxy guardrail for policy-authorized tool use.

The proxy supplies :class:`UserAPIKeyAuth` after authentication.  This adapter binds that
trusted identity to Apparitor's request context, authorizes the tools offered to the model,
then authorizes every tool call in the completed response before it reaches the client.
Request ``metadata``, the OpenAI ``user`` field, messages, and model output are never used as
identity inputs.

Streaming requests are refused before the provider call. LiteLLM exposes tool-call arguments
incrementally, so releasing chunks before the complete call is authorized would create a bypass;
buffering arbitrary provider output would instead expose the proxy to an unbounded-memory DoS.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, AsyncIterable, Callable, Mapping, Sequence
from contextlib import nullcontext
from typing import TYPE_CHECKING, Any

from .adapters import NormalizedToolCall
from .audit import AuditMetadata, audit_metadata_scope
from .config import ScannerConfig
from .decision import Verdict, VerdictResult, VerdictStatus, is_allowed_gateway
from .engine import ReviewPredicate, build_engine, resolve_config
from .errors import AuthZENConfigError, MissingDependencyError
from .mapping import ToolCallMapper
from .models import Subject

try:  # pragma: no cover - exercised by the optional-dependency import test
    from litellm.exceptions import GuardrailRaisedException
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.types.guardrails import GuardrailEventHooks
    from litellm.types.llms.openai import OpenAIFileObject, ResponsesAPIResponse
    from litellm.types.rerank import RerankResponse
    from litellm.types.utils import (
        EmbeddingResponse,
        ImageResponse,
        LiteLLMBatch,
        LiteLLMFineTuningJob,
        ModelResponse,
        TextCompletionResponse,
        TranscriptionResponse,
    )
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.litellm requires LiteLLM. Install it with:\n    pip install 'apparitor[litellm]'"
    ) from exc

if TYPE_CHECKING:
    import httpx
    from litellm.caching.dual_cache import DualCache
    from litellm.proxy._types import UserAPIKeyAuth
    from litellm.types.utils import CallTypesLiteral, LLMResponseTypes, ModelResponseStream

    from .audit import AuditSink
    from .metrics import MetricsSink

IdentityResolver = Callable[["UserAPIKeyAuth"], Subject | None]
AuditMetadataResolver = Callable[["UserAPIKeyAuth"], AuditMetadata]

logger = logging.getLogger("apparitor")

_REFUSAL = "tool call not authorized"
_STREAMING_UNSUPPORTED = "streaming is unsupported by the tool authorization guardrail"


def _default_identity(auth: UserAPIKeyAuth) -> Subject | None:
    """Map LiteLLM's authenticated key owner to an Apparitor user subject."""
    user_id = getattr(auth, "user_id", None)
    if isinstance(user_id, str) and user_id.strip():
        return Subject(type="user", id=user_id)
    return None


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(exclude_none=True)
        return dumped if isinstance(dumped, Mapping) else None
    return None


def _offered_tools(data: Mapping[str, object]) -> list[NormalizedToolCall]:
    """Extract declared tool names for pre-call least-privilege authorization."""
    offered: list[NormalizedToolCall] = []
    raw_tools = data.get("tools")
    if isinstance(raw_tools, Sequence) and not isinstance(raw_tools, (str, bytes)):
        for raw in raw_tools:
            tool = _as_mapping(raw)
            if tool is None:
                raise ValueError("tool declaration is not an object")
            tool_type = tool.get("type")
            is_anthropic_client_tool = tool_type == "custom" and isinstance(
                tool.get("input_schema"), Mapping
            )
            if tool_type not in (None, "function") and not is_anthropic_client_tool:
                raise ValueError("only client-executed function tools are supported")
            function = _as_mapping(tool.get("function"))
            name = function.get("name") if function is not None else tool.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError("tool declaration is missing a name")
            offered.append(NormalizedToolCall(name=name, arguments={}, id=None))

    legacy = data.get("functions")
    if isinstance(legacy, Sequence) and not isinstance(legacy, (str, bytes)):
        for raw in legacy:
            function = _as_mapping(raw)
            name = function.get("name") if function is not None else None
            if not isinstance(name, str) or not name.strip():
                raise ValueError("function declaration is missing a name")
            offered.append(NormalizedToolCall(name=name, arguments={}, id=None))
    return offered


def _chat_tool_calls(response: object) -> list[dict[str, Any]]:
    root = _as_mapping(response)
    if root is None:  # pragma: no cover - guarded by the concrete response type
        raise ValueError("chat response is not an object")
    choices = root.get("choices")
    if not isinstance(choices, Sequence) or isinstance(choices, (str, bytes)):
        raise ValueError("chat response has no choices array")

    calls: list[dict[str, Any]] = []
    for raw_choice in choices:
        choice = _as_mapping(raw_choice)
        message = _as_mapping(choice.get("message")) if choice is not None else None
        if message is None:
            raise ValueError("chat response choice has no message object")
        raw_calls = message.get("tool_calls")
        if raw_calls is not None:
            if not isinstance(raw_calls, Sequence) or isinstance(raw_calls, (str, bytes)):
                raise ValueError("response tool_calls is not an array")
            for raw_call in raw_calls:
                call = _as_mapping(raw_call)
                if call is None:
                    raise ValueError("response tool call is not an object")
                calls.append(dict(call))
        function_call = _as_mapping(message.get("function_call"))
        if message.get("function_call") is not None:
            if function_call is None:
                raise ValueError("legacy function_call is not an object")
            calls.append(
                {
                    "type": "function",
                    "function": dict(function_call),
                }
            )
    return calls


_BENIGN_RESPONSES_OUTPUT_TYPES = frozenset(
    {
        "message",
        "reasoning",
        "function_call_output",
        "computer_call_output",
        "custom_tool_call_output",
        "local_shell_call_output",
        "mcp_list_tools",
        "mcp_approval_request",
        "mcp_approval_response",
        "tool_search_output",
        "compaction",
    }
)


def _responses_api_tool_calls(response: ResponsesAPIResponse) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for raw_item in response.output:
        item = _as_mapping(raw_item)
        if item is None:
            raise ValueError("Responses API output item is not an object")
        item_type = item.get("type")
        if item_type == "function_call":
            name = item.get("name")
            arguments = item.get("arguments")
            if not isinstance(name, str) or not name.strip() or not isinstance(arguments, str):
                raise ValueError("Responses API function_call is malformed")
            calls.append(
                {
                    "id": item.get("call_id") or item.get("id"),
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                }
            )
        elif item_type not in _BENIGN_RESPONSES_OUTPUT_TYPES:
            raise ValueError(f"unsupported executable Responses API output type: {item_type!r}")
    return calls


def _anthropic_tool_calls(response: Mapping[str, object]) -> list[dict[str, Any]]:
    content = response.get("content")
    if not isinstance(content, Sequence) or isinstance(content, (str, bytes)):
        raise ValueError("Anthropic response has no content array")
    calls: list[dict[str, Any]] = []
    for raw_block in content:
        block = _as_mapping(raw_block)
        if block is None:
            raise ValueError("Anthropic content block is not an object")
        if block.get("type") in {"text", "thinking", "redacted_thinking", "compaction"}:
            continue
        if block.get("type") != "tool_use":
            raise ValueError("unsupported executable Anthropic content block")
        name = block.get("name")
        arguments = block.get("input")
        if not isinstance(name, str) or not name.strip() or not isinstance(arguments, Mapping):
            raise ValueError("Anthropic tool_use block is malformed")
        calls.append(
            {
                "type": "tool_use",
                "id": block.get("id"),
                "name": name,
                "input": dict(arguments),
            }
        )
    return calls


def _response_tool_calls(response: object) -> list[dict[str, Any]]:
    """Normalize executable calls while allowing explicit non-executable SDK responses."""
    if isinstance(response, ModelResponse):
        return _chat_tool_calls(response)
    if isinstance(response, ResponsesAPIResponse):
        return _responses_api_tool_calls(response)
    if isinstance(
        response,
        (
            EmbeddingResponse,
            ImageResponse,
            OpenAIFileObject,
            LiteLLMBatch,
            LiteLLMFineTuningJob,
            TextCompletionResponse,
            TranscriptionResponse,
            RerankResponse,
        ),
    ):
        return []
    root = _as_mapping(response)
    if root is not None and root.get("type") == "message" and "content" in root:
        return _anthropic_tool_calls(root)
    raise ValueError(f"unsupported LiteLLM response type: {type(response).__name__}")


class LiteLLMAuthorizationGuardrail(CustomGuardrail):  # type: ignore[misc]  # SDK absent in core-only type checks
    """Fail-closed LiteLLM Proxy guardrail backed by :class:`AuthorizationEngine`.

    The default identity is ``UserAPIKeyAuth.user_id``.  Deployments with a different
    authenticated identity model may provide ``identity_resolver``; its input is still the
    proxy's trusted auth object, never request/model metadata.  Returning ``None`` refuses.
    """

    def __init__(
        self,
        pdp_url: str | None = None,
        *,
        config: ScannerConfig | None = None,
        mapper: ToolCallMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
        audit_sink: AuditSink | None = None,
        audit_fingerprint_key: bytes | None = None,
        audit_metadata_resolver: AuditMetadataResolver | None = None,
        identity_resolver: IdentityResolver = _default_identity,
        authorize_offered_tools: bool = True,
        guardrail_name: str = "apparitor",
        **kwargs: Any,
    ) -> None:
        if audit_sink is not None and audit_metadata_resolver is None:
            raise AuthZENConfigError(
                "audit_metadata_resolver is required when audit_sink is configured"
            )
        required_hooks = self.get_supported_event_hooks()
        selected = kwargs.get("event_hook", required_hooks)
        if not isinstance(selected, (list, tuple)) or set(selected) != set(required_hooks):
            raise AuthZENConfigError("LiteLLM authorization requires pre_call and post_call hooks")
        supported = kwargs.get("supported_event_hooks", required_hooks)
        if not isinstance(supported, (list, tuple)) or set(supported) != set(required_hooks):
            raise AuthZENConfigError("LiteLLM authorization must support both required hooks")
        kwargs["supported_event_hooks"] = required_hooks
        kwargs["event_hook"] = required_hooks
        super().__init__(guardrail_name=guardrail_name, **kwargs)
        self._config = resolve_config(pdp_url, config)
        self._engine = build_engine(
            self._config,
            http_client=http_client,
            mapper=mapper,
            review_predicate=review_predicate,
            metrics=metrics,
            audit_sink=audit_sink,
            audit_fingerprint_key=audit_fingerprint_key,
            audit_integration="litellm",
        )
        self._identity_resolver = identity_resolver
        self._authorize_offered_tools = authorize_offered_tools
        self._audit_metadata_resolver = audit_metadata_resolver

    @classmethod
    def get_supported_event_hooks(cls) -> list[GuardrailEventHooks]:
        return [GuardrailEventHooks.pre_call, GuardrailEventHooks.post_call]

    def _context(self, auth: UserAPIKeyAuth) -> dict[str, object]:
        try:
            subject = self._identity_resolver(auth)
        except Exception as exc:
            raise self._boundary_refusal("trusted identity resolver failed") from exc
        if not isinstance(subject, Subject):
            raise self._boundary_refusal("authenticated caller has no authorization subject")
        return {"subject": subject, "user_id": subject.id}

    def _audit_scope(self, auth: UserAPIKeyAuth) -> Any:
        resolver = self._audit_metadata_resolver
        if resolver is None:
            return nullcontext()
        try:
            metadata = resolver(auth)
            if not isinstance(metadata, AuditMetadata):
                raise TypeError("resolver did not return AuditMetadata")
        except (Exception, asyncio.CancelledError):
            logger.warning("apparitor: LiteLLM audit metadata resolution failed")
            metadata = None
        return audit_metadata_scope(metadata)

    def _refusal(self, reason: str, *, blocked_content: bool = False) -> GuardrailRaisedException:
        return GuardrailRaisedException(
            guardrail_name=self.guardrail_name,
            message=reason,
            should_wrap_with_default_message=False,
            status_code=403,
            blocked_content=blocked_content,
        )

    def _boundary_refusal(self, reason: str) -> GuardrailRaisedException:
        """Record a refusal that occurred before the engine could produce a verdict."""
        self._engine.record_refusal()
        return self._refusal(reason)

    async def _authorize(
        self, calls: list[NormalizedToolCall] | list[dict[str, Any]], auth: UserAPIKeyAuth
    ) -> None:
        context = self._context(auth)
        try:
            if calls and isinstance(calls[0], NormalizedToolCall):
                verdict = await self._engine.evaluate_normalized(calls, context)
            else:
                verdict = await self._engine.evaluate_tool_calls(calls, context)  # type: ignore[arg-type]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise self._boundary_refusal(_REFUSAL) from exc
        if not is_allowed_gateway(verdict):
            raise self._refusal(_REFUSAL, blocked_content=_is_policy_block(verdict))

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict[str, Any],
        call_type: CallTypesLiteral,
    ) -> dict[str, Any]:
        del cache
        with self._audit_scope(user_api_key_dict):
            if call_type in ("send_message", "asend_message"):
                raise self._boundary_refusal(
                    "A2A proxy routes require an execution-boundary authorization adapter"
                )
            if data.get("background") is True:
                raise self._boundary_refusal("background responses are unsupported")
            if data.get("stream") is True:
                raise self._boundary_refusal(_STREAMING_UNSUPPORTED)
            if any(data.get(field) is not None for field in ("mcp_servers", "web_search_options")):
                raise self._boundary_refusal("provider-executed tools are unsupported")
            try:
                offered = _offered_tools(data)
            except Exception as exc:
                raise self._boundary_refusal("tool declarations could not be verified") from exc
            if offered and self._authorize_offered_tools:
                await self._authorize(offered, user_api_key_dict)
            return data

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: UserAPIKeyAuth,
        response: LLMResponseTypes,
    ) -> LLMResponseTypes:
        del data
        with self._audit_scope(user_api_key_dict):
            try:
                calls = _response_tool_calls(response)
            except Exception as exc:
                raise self._boundary_refusal(
                    "response could not be verified for tool authorization"
                ) from exc
            if calls:
                await self._authorize(calls, user_api_key_dict)
            return response

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: AsyncIterable[ModelResponseStream],
        request_data: dict[str, Any],
    ) -> AsyncGenerator[ModelResponseStream, None]:
        del response, request_data
        with self._audit_scope(user_api_key_dict):
            if False:  # preserve the async-generator contract without releasing any chunk
                yield  # pragma: no cover
            raise self._boundary_refusal(_STREAMING_UNSUPPORTED)

    async def aclose(self) -> None:
        """Close an Apparitor-owned backend client."""
        await self._engine.aclose()


def _is_policy_block(verdict: VerdictResult) -> bool:
    return verdict.verdict is Verdict.BLOCK and verdict.status is VerdictStatus.SUCCESS
