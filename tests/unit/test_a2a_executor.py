"""A2A executor adapter tests — verdict → execute/refuse mapping over a real A2A server.

Requires a2a-sdk with its [http-server] extra (the in-process JSON-RPC harness); skipped
automatically when it is not installed (a dedicated CI job installs it). The server is
driven end-to-end: Starlette routes over ``httpx.ASGITransport``, the official A2A client
on top. The PDP is mocked with ``httpx.MockTransport`` on a bring-your-own client — NOT
respx, which would also intercept the in-process A2A client's httpx traffic. Caller
identity is injected through a custom ``ServerCallContextBuilder`` — the exact seam a
deployment's authentication middleware populates.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("a2a")
pytest.importorskip("sse_starlette")  # the SDK's [http-server] extra

import a2a.types as t  # noqa: E402
from a2a.auth.user import User  # noqa: E402
from a2a.client import ClientConfig, ClientFactory  # noqa: E402
from a2a.server.agent_execution import AgentExecutor, RequestContext  # noqa: E402
from a2a.server.context import ServerCallContext  # noqa: E402
from a2a.server.events import EventQueue  # noqa: E402
from a2a.server.request_handlers import DefaultRequestHandler  # noqa: E402
from a2a.server.routes import (  # noqa: E402
    DefaultServerCallContextBuilder,
    ServerCallContextBuilder,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore  # noqa: E402
from starlette.applications import Starlette  # noqa: E402

from apparitor import Subject  # noqa: E402
from apparitor.a2a import A2AAuthorizationExecutor  # noqa: E402
from apparitor.errors import AuthZENConfigError  # noqa: E402
from apparitor.mapping import subject_scope  # noqa: E402

_ALICE = Subject(type="user", id="alice@acme.com")

_CARD = t.AgentCard(
    name="travel-agent",
    description="demo",
    version="1",
    supported_interfaces=[t.AgentInterface(url="http://test/a2a", protocol_binding="JSONRPC")],
    capabilities=t.AgentCapabilities(streaming=False),
    default_input_modes=["text"],
    default_output_modes=["text"],
    skills=[t.AgentSkill(id="book_flight", name="book_flight", description="b", tags=[])],
)


class _Peer(User):
    """An authenticated A2A peer, as a deployment's authn middleware would establish."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_name(self) -> str:
        return self._name


class _ContextBuilder(DefaultServerCallContextBuilder):
    """Injects a fixed user and/or state — the seam real authn middleware populates —
    while keeping the default builder's header/version handling intact."""

    def __init__(self, user: User | None = None, state: dict[str, Any] | None = None) -> None:
        self._user = user
        self._state = state or {}

    def build(self, request: Any) -> ServerCallContext:
        context = super().build(request)
        if self._user is not None:
            context.user = self._user
        context.state.update(self._state)
        return context


class _EchoExecutor(AgentExecutor):
    """The guarded delegate; records whether it actually ran."""

    def __init__(self) -> None:
        self.executed = 0
        self.cancelled = 0

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.executed += 1
        reply = t.Message(
            message_id="r1",
            role=t.Role.ROLE_AGENT,
            parts=[t.Part(text="booked")],
            context_id=context.context_id or "",
            task_id=context.task_id or "",
        )
        await event_queue.enqueue_event(reply)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.cancelled += 1


class _PDP:
    """An httpx.MockTransport PDP capturing every evaluation request."""

    def __init__(self, decision: bool = True, status_code: int = 200) -> None:
        self.requests: list[dict[str, Any]] = []
        self._decision = decision
        self._status = status_code

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if self._status != 200:
            return httpx.Response(self._status)
        return httpx.Response(200, json={"decision": self._decision})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _guarded(
    delegate: AgentExecutor, pdp: _PDP, make_config: Any, **kwargs: Any
) -> A2AAuthorizationExecutor:
    return A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id=None, max_retries=0),
        agent_label="travel-agent",
        http_client=pdp.client(),
        **kwargs,
    )


def _a2a_client(executor: AgentExecutor, builder: ServerCallContextBuilder | None = None) -> Any:
    handler = DefaultRequestHandler(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=_CARD
    )
    routes = create_jsonrpc_routes(handler, rpc_url="/a2a", context_builder=builder)
    app = Starlette(routes=routes)
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(_CARD)


def _request(tenant: str = "") -> t.SendMessageRequest:
    return t.SendMessageRequest(
        tenant=tenant,
        message=t.Message(message_id="m1", role=t.Role.ROLE_USER, parts=[t.Part(text="book it")]),
    )


async def _send(client: Any, tenant: str = "") -> list[Any]:
    return [event async for event in client.send_message(_request(tenant))]


def test_constructor_validates(make_config) -> None:
    delegate = _EchoExecutor()
    with pytest.raises(AuthZENConfigError, match="pdp_url or config"):
        A2AAuthorizationExecutor(delegate, agent_label="x")
    with pytest.raises(AuthZENConfigError, match="agent_label"):
        A2AAuthorizationExecutor(delegate, config=make_config(), agent_label="a/b")
    with pytest.raises(AuthZENConfigError, match="reserved"):
        A2AAuthorizationExecutor(
            delegate, config=make_config(), agent_label="x", subject_type="workload"
        )


def test_constructor_rejects_both_pdp_url_and_config(make_config) -> None:
    with pytest.raises(AuthZENConfigError, match="not both"):
        A2AAuthorizationExecutor(
            _EchoExecutor(), "http://pdp.test", config=make_config(), agent_label="x"
        )


@pytest.mark.asyncio
async def test_authenticated_peer_allowed(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    # tenant arrives on the REQUEST (the SDK's dispatcher copies it onto the call
    # context) — it is protocol routing data, not a host assertion.
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        events = await _send(client, tenant="acme")
    assert delegate.executed == 1
    assert any("booked" in str(event) for event in events)
    sent = pdp.requests[0]
    assert sent["subject"]["type"] == "agent"
    assert sent["subject"]["id"] == "planner-agent"
    assert sent["action"]["name"] == "agent.invoke"
    assert sent["resource"]["type"] == "a2a_agent"
    assert sent["resource"]["id"] == "travel-agent"
    assert sent["context"]["tenant"] == "acme"


@pytest.mark.asyncio
async def test_denied_invocation_refused_with_generic_reason(make_config) -> None:
    pdp = _PDP(decision=False)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert delegate.executed == 0
    assert len(pdp.requests) == 1  # a genuine PDP deny, not a pre-engine refusal
    message = str(excinfo.value).lower()
    for fragment in ("pdp", "unavailable", "http", "subject", "config"):
        assert fragment not in message


@pytest.mark.asyncio
async def test_unauthenticated_caller_refused_without_pdp_trip(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    # agent_id configured but allow_static_subject defaults to False: an anonymous
    # network caller must never be authorized as the static subject.
    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id="bot-123", max_retries=0),
        agent_label="travel-agent",
        http_client=pdp.client(),
    )
    client = _a2a_client(guard)  # default builder: UnauthenticatedUser
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_static_subject_requires_opt_in(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id="bot-123", max_retries=0),
        agent_label="travel-agent",
        allow_static_subject=True,
        http_client=pdp.client(),
    )
    client = _a2a_client(guard)
    async with guard:
        await _send(client)
    assert delegate.executed == 1
    assert pdp.requests[0]["subject"]["id"] == "bot-123"
    # The static fallback is typed by config.subject_type, not the constructor knob.
    assert pdp.requests[0]["subject"]["type"] == "agent"


@pytest.mark.asyncio
async def test_state_injected_subject_when_unauthenticated(make_config) -> None:
    # The per-request injection seam is ServerCallContext.state, populated by the
    # deployment's context builder.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(state={"subject": _ALICE}))
    async with guard:
        await _send(client)
    assert pdp.requests[0]["subject"]["id"] == "alice@acme.com"


@pytest.mark.asyncio
async def test_authenticated_peer_wins_over_state_subject(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(
        guard, _ContextBuilder(user=_Peer("planner-agent"), state={"subject": _ALICE})
    )
    async with guard:
        await _send(client)
    assert pdp.requests[0]["subject"]["id"] == "planner-agent"


@pytest.mark.asyncio
async def test_ambient_contextvar_subject_is_ignored(make_config) -> None:
    # The executor runs in the SDK's detached producer task, where ambient contextvars
    # are snapshotted at task creation and go STALE across turns — consulting them would
    # be a cross-request identity leak. They must be ignored entirely.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard)
    async with guard:
        with subject_scope(_ALICE), pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_caller_metadata_never_reaches_policy_context(make_config) -> None:
    # Message metadata is caller-controlled; forwarding it into the AuthZEN context
    # would let the caller influence policy inputs. With no tenant and no state attrs,
    # the request must carry no context member at all.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    request = _request()
    request.message.metadata.update({"user_id": "mallory", "conversation_id": "evil"})
    async with guard:
        async for _ in client.send_message(request):
            pass
    assert "context" not in pdp.requests[0]


@pytest.mark.asyncio
async def test_refusal_metric_counts_pre_engine_refusals(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard)
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert guard.metrics.decisions == {("block", "error"): 1}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_streaming_denial_surfaces_generic_error(make_config) -> None:
    pdp = _PDP(decision=False)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    card = t.AgentCard()
    card.CopyFrom(_CARD)
    card.capabilities.streaming = True
    handler = DefaultRequestHandler(
        agent_executor=guard, task_store=InMemoryTaskStore(), agent_card=card
    )
    routes = create_jsonrpc_routes(
        handler, rpc_url="/a2a", context_builder=_ContextBuilder(user=_Peer("planner-agent"))
    )
    hc = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=Starlette(routes=routes)), base_url="http://test"
    )
    client = ClientFactory(ClientConfig(httpx_client=hc, streaming=True)).create(card)
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            async for _ in client.send_message(_request()):
                pass
    assert delegate.executed == 0
    assert len(pdp.requests) == 1  # a genuine PDP deny on the streaming path


@pytest.mark.asyncio
async def test_skill_resolver_scopes_resource(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config, skill_resolver=lambda context: "book_flight")
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        await _send(client)
    assert pdp.requests[0]["resource"]["type"] == "a2a_skill"
    assert pdp.requests[0]["resource"]["id"] == "travel-agent/book_flight"


@pytest.mark.asyncio
async def test_unusable_skill_refuses_without_pdp_trip(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    calls: list[str] = []

    def resolver(context: RequestContext) -> str:
        calls.append("hit")
        return "a/b"

    guard = _guarded(delegate, pdp, make_config, skill_resolver=resolver)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert calls == ["hit"]  # the resolver ran — this is its refusal, not a subject one
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_raising_skill_resolver_refuses(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()

    calls: list[str] = []

    def boom(context: RequestContext) -> str:
        calls.append("hit")
        raise RuntimeError("secret-resolver-detail")

    guard = _guarded(delegate, pdp, make_config, skill_resolver=boom)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert calls == ["hit"]
    assert delegate.executed == 0
    assert pdp.requests == []
    assert "secret-resolver-detail" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_pdp_error_fails_closed_without_leaking_detail(make_config) -> None:
    pdp = _PDP(status_code=503)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized") as excinfo:
            await _send(client)
    assert delegate.executed == 0
    assert len(pdp.requests) == 1
    message = str(excinfo.value).lower()
    for fragment in ("pdp", "unavailable", "503", "retr"):
        assert fragment not in message


@pytest.mark.asyncio
async def test_human_review_refuses_distinctly(make_config) -> None:
    delegate = _EchoExecutor()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": True, "context": {"step_up": True}})

    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id=None, max_retries=0),
        agent_label="travel-agent",
        review_predicate=lambda ctx: bool(ctx.get("step_up")),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="human approval"):
            await _send(client)
    assert delegate.executed == 0


@pytest.mark.asyncio
async def test_cancel_passes_through_to_delegate(make_config) -> None:
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    async with guard:
        await guard.cancel(None, None)  # type: ignore[arg-type]  # delegate ignores both
    assert delegate.cancelled == 1


# --- panel-review hardening cases -----------------------------------------------------


def test_workload_reservation_covers_static_fallback(make_config) -> None:
    with pytest.raises(ValueError, match="reserved"):
        A2AAuthorizationExecutor(
            _EchoExecutor(),
            config=make_config(subject_type="workload"),
            agent_label="x",
            allow_static_subject=True,
        )


@pytest.mark.asyncio
async def test_custom_subject_type_for_authenticated_peers(make_config) -> None:
    pdp = _PDP(decision=True)
    guard = _guarded(_EchoExecutor(), pdp, make_config, subject_type="user")
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("alice@acme.com")))
    async with guard:
        await _send(client)
    assert pdp.requests[0]["subject"]["type"] == "user"
    assert pdp.requests[0]["subject"]["id"] == "alice@acme.com"


@pytest.mark.asyncio
async def test_non_subject_state_value_is_ignored(make_config) -> None:
    # Only a real Subject instance counts: a string (e.g. smuggled through some state
    # plumbing) must not mint an identity.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(state={"subject": "mallory"}))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


@pytest.mark.asyncio
async def test_caller_headers_cannot_mint_subject_or_context(make_config) -> None:
    # The default builder stores request headers NESTED under state["headers"], so a
    # caller sending "subject"/"user_id" headers can neither mint an identity nor leak
    # attributes into the AuthZEN context.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    handler = DefaultRequestHandler(
        agent_executor=guard, task_store=InMemoryTaskStore(), agent_card=_CARD
    )
    routes = create_jsonrpc_routes(
        handler, rpc_url="/a2a", context_builder=_ContextBuilder(user=_Peer("planner-agent"))
    )
    hc = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=Starlette(routes=routes)),
        base_url="http://test",
        headers={"subject": "mallory", "user_id": "mallory", "conversation_id": "evil"},
    )
    client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(_CARD)
    async with guard:
        await _send(client)
    sent = pdp.requests[0]
    assert sent["subject"]["id"] == "planner-agent"
    assert "context" not in sent


@pytest.mark.asyncio
async def test_authenticated_user_name_is_stripped(make_config) -> None:
    # Whitespace variants of one peer must not split policy keys.
    pdp = _PDP(decision=True)
    guard = _guarded(_EchoExecutor(), pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("  planner-agent  ")))
    async with guard:
        await _send(client)
    assert pdp.requests[0]["subject"]["id"] == "planner-agent"


@pytest.mark.asyncio
async def test_authenticated_but_nameless_user_refuses(make_config) -> None:
    # A broken authn integration yielding an empty name must refuse, never mint
    # Subject(id="") or fall through to a weaker subject.
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id="bot-123", max_retries=0),
        agent_label="travel-agent",
        allow_static_subject=True,
        http_client=pdp.client(),
    )
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("   ")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


# --- dual-principal boundary (boundary_subject) tests --------------------------------


class _BatchPDP:
    """Mock PDP that handles both single and batch evaluation endpoints.

    Batch responses carry per-leg decisions, keyed by subject id.
    Single-evaluation responses use a fixed decision.
    """

    def __init__(self, decisions_by_subject: dict[str, bool] | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self._decisions = decisions_by_subject or {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        if "evaluations" in body:
            # Batch path: return per-leg decisions.
            evals = [
                {"decision": self._decisions.get(item["subject"]["id"], True)}
                for item in body["evaluations"]
            ]
            return httpx.Response(200, json={"evaluations": evals})
        # Single path.
        subject_id = body.get("subject", {}).get("id", "")
        decision = self._decisions.get(subject_id, True)
        return httpx.Response(200, json={"decision": decision})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _guarded_with_boundary(
    delegate: AgentExecutor,
    pdp: _BatchPDP,
    make_config: Any,
    boundary_subject: Any,
    **kwargs: Any,
) -> A2AAuthorizationExecutor:
    return A2AAuthorizationExecutor(
        delegate,
        config=make_config(agent_id=None, max_retries=0),
        agent_label="travel-agent",
        boundary_subject=boundary_subject,
        http_client=pdp.client(),
        **kwargs,
    )


_BOUNDARY = Subject(type="agent", id="travel-bot")


@pytest.mark.asyncio
async def test_boundary_both_allow_executes(make_config) -> None:
    # Both caller and boundary allow → delegate runs.
    pdp = _BatchPDP({"planner-agent": True, "travel-bot": True})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        await _send(client)
    assert delegate.executed == 1
    assert len(pdp.requests) == 1  # one batch round trip


@pytest.mark.asyncio
async def test_boundary_caller_deny_refuses(make_config) -> None:
    # Caller denied, boundary allowed → refused.
    pdp = _BatchPDP({"planner-agent": False, "travel-bot": True})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0


@pytest.mark.asyncio
async def test_boundary_boundary_deny_refuses(make_config) -> None:
    # Caller allowed, boundary denied → refused even though caller's grant is valid.
    pdp = _BatchPDP({"planner-agent": True, "travel-bot": False})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0


@pytest.mark.asyncio
async def test_boundary_both_deny_refuses(make_config) -> None:
    pdp = _BatchPDP({"planner-agent": False, "travel-bot": False})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0


@pytest.mark.asyncio
async def test_boundary_batch_wire_format(make_config) -> None:
    # The batch must carry exactly two evaluations: caller first, boundary second,
    # and both legs must share the same tenant context.
    pdp = _BatchPDP({"planner-agent": True, "travel-bot": True})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        await _send(client, tenant="acme")
    sent = pdp.requests[0]
    assert "evaluations" in sent
    evals = sent["evaluations"]
    assert len(evals) == 2
    assert evals[0]["subject"]["id"] == "planner-agent"
    assert evals[1]["subject"]["id"] == "travel-bot"
    # Both legs carry the same tenant context (Amendment 1).
    assert evals[0].get("context", {}).get("tenant") == "acme"
    assert evals[1].get("context", {}).get("tenant") == "acme"


@pytest.mark.asyncio
async def test_boundary_collapse_guard_refuses_without_pdp(make_config, caplog) -> None:
    # When boundary == resolved caller the AND collapses; must refuse before any PDP call.
    import logging

    pdp = _BatchPDP({"planner-agent": True})
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(
        delegate, pdp, make_config, Subject(type="agent", id="planner-agent")
    )
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    with caplog.at_level(logging.WARNING, logger="apparitor"):
        async with guard:
            with pytest.raises(Exception, match="not authorized"):
                await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []
    assert "collapse" in caplog.text


@pytest.mark.asyncio
async def test_boundary_unresolvable_caller_refuses_without_pdp(make_config) -> None:
    # Unresolvable caller still refuses before any PDP trip even when boundary is set.
    pdp = _BatchPDP()
    delegate = _EchoExecutor()
    guard = _guarded_with_boundary(delegate, pdp, make_config, _BOUNDARY)
    client = _a2a_client(guard)  # no authenticated user, no static subject
    async with guard:
        with pytest.raises(Exception, match="not authorized"):
            await _send(client)
    assert delegate.executed == 0
    assert pdp.requests == []


def test_boundary_workload_subject_rejected_at_construction(make_config) -> None:
    with pytest.raises(ValueError, match="reserved"):
        A2AAuthorizationExecutor(
            _EchoExecutor(),
            config=make_config(agent_id=None, max_retries=0),
            agent_label="travel-agent",
            boundary_subject=Subject(type="workload", id="svc-1"),
            http_client=_BatchPDP().client(),
        )


def test_boundary_cache_warning_emitted(make_config, caplog) -> None:
    import logging

    with caplog.at_level(logging.WARNING, logger="apparitor"):
        A2AAuthorizationExecutor(
            _EchoExecutor(),
            config=make_config(agent_id=None, max_retries=0, cache_enabled=True),
            agent_label="travel-agent",
            boundary_subject=_BOUNDARY,
            http_client=_BatchPDP().client(),
        )
    assert "never be consulted" in caplog.text


# --- gateway predicate (is_allowed_gateway, not is_allowed_inline) -------------------


@pytest.mark.asyncio
async def test_skip_verdict_refuses_at_gateway_boundary(make_config) -> None:
    # A SKIP verdict at a network boundary means the engine received an empty request
    # list — an unexpected state that must refuse, not pass through.  This pin ensures
    # the A2A executor uses is_allowed_gateway (SKIP → refuse) rather than
    # is_allowed_inline (SKIP → pass through), which would be an authorization bypass
    # whenever the engine is coerced into returning SKIP on a submitted call.
    from unittest.mock import AsyncMock, patch

    from apparitor.decision import Verdict, VerdictResult, VerdictStatus

    skip_result = VerdictResult(
        verdict=Verdict.SKIP, reason="no requests", status=VerdictStatus.SKIPPED
    )
    pdp = _PDP(decision=True)
    delegate = _EchoExecutor()
    guard = _guarded(delegate, pdp, make_config)
    client = _a2a_client(guard, _ContextBuilder(user=_Peer("planner-agent")))
    async with guard:
        with (
            patch.object(guard._engine, "evaluate_requests", AsyncMock(return_value=skip_result)),
            pytest.raises(Exception, match="not authorized"),
        ):
            await _send(client)
    assert delegate.executed == 0  # SKIP must not reach the delegate
