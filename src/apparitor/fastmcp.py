"""FastMCP server-middleware adapter (thin adapter over :class:`AuthorizationEngine`).

This is the **only** module that imports FastMCP. The import is guarded so that importing
it without ``fastmcp`` installed yields a clear
:class:`~apparitor.errors.MissingDependencyError` rather than an opaque ``ImportError``.

It binds the firewall-free :class:`AuthorizationEngine` behind a FastMCP **middleware** so
every MCP ``tools/call`` is authorized server-side, *before* the tool executes — the same
engine, mapper, fail-closed semantics and metrics as the LlamaFirewall scanner and the NeMo
rail; only the boundary differs. Unlike the in-runtime firewall adapters, the subject here
can come from a **validated** identity: the OAuth access token FastMCP's auth layer
verified for the request — never from anything the model produced.

Subject resolution (first match wins; no match refuses the call):

1. The verified access token's ``sub`` claim → ``Subject(type="user", id=<sub>)``
   (``subject_claim`` / ``subject_type`` are constructor knobs). A token *without* a
   usable claim refuses — unless ``allow_workload_subject=True``, which maps such a
   client-credentials token to the distinct ``Subject(type="workload", id=<client_id>)``
   so machine policies are written on their own terms; a workload identity is **never**
   coerced into a user subject or silently downgraded to a fallback.
2. A host-injected trusted subject: ``current_request_context["subject"]`` or
   :func:`~apparitor.mapping.subject_scope` — out-of-band, as with the other adapters.
3. ``config.agent_id``, **only** when ``allow_static_subject=True``. Off by default: on a
   network transport a static fallback would authorize every anonymous caller as that one
   subject (a confused deputy). Opt in only for local/stdio servers.

The default mapper is :class:`~apparitor.mapping.MCPResourceMapper`, so the resource id is
server-scoped (``"<server>/<tool>"``): ``server_label`` if given, else the name of the
FastMCP server the call arrived on. Renaming the server changes resource ids (and
ALLOW-cache keys), and under server composition (``mount``) the derived name is not
guaranteed stable across the supported FastMCP range (2.14 through 4.x). **Pin
``server_label`` whenever the server may be renamed or mounted** so policy keys stay
stable.

Verdict mapping is fail-closed: only a clean ``ALLOW`` reaches the tool. ``BLOCK``,
``HUMAN_REVIEW`` (MCP has no human-in-the-loop pause; refusal is surfaced distinctly so a
host can escalate), mapper abstention (``SKIP`` — here always exactly one call is
submitted, so abstention would otherwise silently execute) and any error refuse by raising
``ToolError``. Refusal messages are deliberately generic: ``ToolError`` text reaches the
(untrusted) client and model, so the rich verdict/reason stays in the operator decision
log and metrics. Note the decision log records the subject id — with token-derived
subjects that is the OAuth ``sub``; route the ``apparitor`` logger accordingly.

Enforcement scope: ``tools/call``, ``resources/read`` (action ``resource.read``, resource
``{type: "mcp_resource", id: <uri>}`` — URIs are kept verbatim, with the server label in
``properties``), and ``prompts/get`` (action ``prompt.get``, resource
``{type: "mcp_prompt", id: "<server>/<prompt>"}``) are all gated by default, each behind
the same subject chain and fail-closed verdict mapping; ``gate_resources`` /
``gate_prompts`` opt a hook out where only tool gating is wanted. Resource *templates*
reach the gate with the concrete expanded URI, so policies over templates need
wildcard/prefix matching. ``tools/list`` shaping is opt-in (``filter_listings=True``):
advisory UX that hides tools whose ``tools/call`` the subject would be denied (one batch
PDP round trip per listing — MCP clients re-list often, so budget the PDP accordingly —
and anything not a clean ALLOW, or any fault, hides). Visibility caveats: PDP policy
changes alter what a re-list returns but emit no ``list_changed`` notification, and only
``tools/list`` is filtered — ``resources/list``, ``resources/templates/list`` and
``prompts/list`` still advertise names/URIs to every caller even though reads/gets are
gated. The ``mapper`` parameter governs tool calls and listing filtering; resource/prompt
tuples are shaped by the adapter itself (they are not tool calls), so a custom mapper does
not affect them. Deployment requirements: register the middleware on every server whose
components must be gated (a mounted sub-server is covered only when calls flow through
the parent) and order it after any custom auth middleware so the token is populated.
FastMCP never tears middleware down, so closing is the host's job (``aclose()``).

Wiring::

    from fastmcp import FastMCP
    from apparitor.fastmcp import FastMCPAuthorizationMiddleware

    server = FastMCP("files", auth=...)  # auth yields the validated token identity
    server.add_middleware(FastMCPAuthorizationMiddleware(pdp_url="https://pdp.internal"))
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .adapters import NormalizedToolCall
from .decision import (
    VerdictResult,
    is_allowed_gateway,
    refusal_message,
    validate_gateway_subject_config,
)
from .engine import ReviewPredicate, build_engine, resolve_config
from .errors import MissingDependencyError
from .mapping import (
    MCP_SERVER_LABEL_KEY,
    MCPResourceMapper,
    current_request_context,
    request_context_attrs,
    request_scoped_subject,
)
from .models import Action, EvaluationRequest, Resource, Subject

try:  # pragma: no cover - exercised via import-guard tests
    from fastmcp.exceptions import PromptError, ResourceError, ToolError
    from fastmcp.server.dependencies import get_access_token
    from fastmcp.server.middleware import Middleware
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.fastmcp requires FastMCP. Install it with:\n    pip install 'apparitor[fastmcp]'"
    ) from exc

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx
    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.tool import ToolResult

    from .audit import AuditSink
    from .config import ScannerConfig
    from .mapping import ToolCallMapper
    from .metrics import MetricsSink

logger = logging.getLogger("apparitor")


class FastMCPAuthorizationMiddleware(Middleware):  # type: ignore[misc]  # fastmcp may be absent in the lint env (base is Any)
    """Authorizes MCP tool calls against an AuthZEN PDP from inside a FastMCP server.

    Construct it like the other adapters — a ``pdp_url`` or a full :class:`ScannerConfig` —
    then ``server.add_middleware(...)``. A subject must be resolvable (validated token,
    host-injected subject, or the opt-in static fallback) or the call is refused.

    ``boundary_subject`` is **deployment-time** only, never per-request. When set, every
    ``resources/read`` and ``prompts/get`` request is evaluated as a two-request batch —
    the resolved caller leg AND the boundary leg — using the same AND/all-allow-or-block
    semantics as :class:`~apparitor.mapping.DualPrincipalMapper`. It does **not** cover
    ``tools/call`` or listing — use ``mapper=DualPrincipalMapper(config)`` for those; a full
    deployment sets both. Set it when the serving agent's own permission boundary must be
    enforced on resource/prompt access regardless of what the caller is permitted.
    """

    def __init__(
        self,
        pdp_url: str | None = None,
        *,
        config: ScannerConfig | None = None,
        server_label: str | None = None,
        subject_type: str = "user",
        subject_claim: str = "sub",
        allow_static_subject: bool = False,
        allow_workload_subject: bool = False,
        filter_listings: bool = False,
        gate_resources: bool = True,
        gate_prompts: bool = True,
        boundary_subject: Subject | None = None,
        mapper: ToolCallMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
        review_predicate: ReviewPredicate | None = None,
        metrics: MetricsSink | None = None,
        audit_sink: AuditSink | None = None,
        audit_fingerprint_key: bytes | None = None,
    ) -> None:
        super().__init__()
        # Resolve config first so the workload guards can check config.subject_type.
        config = resolve_config(pdp_url, config)
        validate_gateway_subject_config(
            config,
            subject_type=subject_type,
            allow_static_subject=allow_static_subject,
            boundary_subject=boundary_subject,
        )
        self._config = config
        self._server_label = server_label
        self._subject_type = subject_type
        self._subject_claim = subject_claim
        self._allow_static_subject = allow_static_subject
        self._allow_workload_subject = allow_workload_subject
        self._filter_listings = filter_listings
        self._gate_resources = gate_resources
        self._gate_prompts = gate_prompts
        self._boundary_subject = boundary_subject
        self._engine = build_engine(
            config,
            http_client=http_client,
            mapper=mapper or MCPResourceMapper(config),
            review_predicate=review_predicate,
            metrics=metrics,
            audit_sink=audit_sink,
            audit_fingerprint_key=audit_fingerprint_key,
            audit_integration="fastmcp",
        )
        # One line an operator can find when diagnosing "why is X denied after upgrade".
        logger.info(
            "apparitor: FastMCP middleware gating tools/call%s%s%s%s",
            ", resources/read" if gate_resources else "",
            ", prompts/get" if gate_prompts else "",
            "; filtering tools/list" if filter_listings else "",
            f"; boundary={boundary_subject.type}:{boundary_subject.id}"
            if boundary_subject is not None
            else "",
        )

    @property
    def metrics(self) -> MetricsSink:
        """The engine's metrics sink (latency histogram + cache-hit counter)."""
        return self._engine.metrics

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Authorize the tool call; only a clean ALLOW reaches ``call_next``."""
        return await self._gate(
            await_verdict=self._authorize(context),
            call_next=call_next,
            context=context,
            error_cls=ToolError,
            noun="tool call",
        )

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Any],
    ) -> Any:
        """Hide tools the subject may not call (opt-in via ``filter_listings``).

        Advisory shaping, not the enforcement invariant — ``on_call_tool`` still gates
        every execution. Fail-closed: no resolvable subject, a non-ALLOW verdict, or any
        fault hides (an error must conceal, never reveal).
        """
        tools = await call_next(context)
        if not self._filter_listings:
            return tools
        try:
            names = [_listed_name(tool) for tool in tools]
            visible = await self._visible_tools(context, names)
            return [tool for tool, name in zip(tools, names, strict=True) if name in visible]
        except Exception:
            logger.exception("apparitor: listing filter error (hiding all tools)")
            self._engine.record_refusal()
            return []

    async def on_read_resource(
        self,
        context: MiddlewareContext[mt.ReadResourceRequestParams],
        call_next: CallNext[mt.ReadResourceRequestParams, Any],
    ) -> Any:
        """Authorize the resource read (action ``resource.read``); only ALLOW reads."""
        if not self._gate_resources:
            return await call_next(context)
        return await self._gate(
            await_verdict=self._authorize_shaped(context, self._resource_request),
            call_next=call_next,
            context=context,
            error_cls=ResourceError,
            noun="resource read",
        )

    async def on_get_prompt(
        self,
        context: MiddlewareContext[mt.GetPromptRequestParams],
        call_next: CallNext[mt.GetPromptRequestParams, Any],
    ) -> Any:
        """Authorize the prompt fetch (action ``prompt.get``); only ALLOW fetches."""
        if not self._gate_prompts:
            return await call_next(context)
        return await self._gate(
            await_verdict=self._authorize_shaped(context, self._prompt_request),
            call_next=call_next,
            context=context,
            error_cls=PromptError,
            noun="prompt",
        )

    async def _gate(
        self,
        await_verdict: Any,
        call_next: CallNext[Any, Any],
        context: MiddlewareContext[Any],
        error_cls: type[Exception],
        noun: str,
    ) -> Any:
        """Shared gate: evaluate, check, pass or raise. Preserves exact fail-closed behavior.

        catch → log.exception → record_pre_engine_refusal → raise surface error from None;
        None verdict (no subject) → record_pre_engine_refusal → raise.
        """
        try:
            verdict = await await_verdict
        except Exception:
            # Defense in depth: an adapter-level fault must refuse, never execute. The
            # generic message is deliberate — exception text must not reach the client.
            logger.exception("apparitor: FastMCP authorization middleware error (refusing)")
            self._engine.record_refusal()
            raise error_cls(refusal_message(noun, None)) from None
        if verdict is not None and is_allowed_gateway(verdict):
            return await call_next(context)
        if verdict is None:
            # No resolvable subject: the engine never ran, so this refusal is invisible to
            # its metrics unless we count it here (else an all-misconfigured fleet logs zero).
            self._engine.record_refusal()
        raise error_cls(refusal_message(noun, verdict))

    async def _authorize(
        self, context: MiddlewareContext[mt.CallToolRequestParams]
    ) -> VerdictResult | None:
        """Evaluate the call; ``None`` means no resolvable subject (refuse, no PDP trip)."""
        ctx = self._request_context(context)
        if ctx is None:
            return None
        call = NormalizedToolCall(
            name=context.message.name, arguments=dict(context.message.arguments or {})
        )
        return await self._engine.evaluate_normalized([call], request_context=ctx)

    async def _authorize_shaped(
        self,
        context: MiddlewareContext[Any],
        shape: Callable[[MiddlewareContext[Any], dict[str, Any]], EvaluationRequest | None],
    ) -> VerdictResult | None:
        """Evaluate an adapter-shaped request; ``None`` refuses without a PDP trip
        (no resolvable subject, or ``shape`` could not build a sound policy key).
        When boundary_subject is set the caller leg and boundary leg are sent as one
        batch; AuthZENConfigError from the collapse guard logs a WARNING and maps to
        the generic refusal path (reason in operator log only)."""
        ctx = self._request_context(context)
        if ctx is None:
            return None
        request = shape(context, ctx)
        if request is None:
            return None
        return await self._engine.evaluate_with_boundary(request, self._boundary_subject)

    async def _visible_tools(self, context: MiddlewareContext[Any], names: list[str]) -> set[str]:
        """The subset of ``names`` whose ``tools/call`` the subject would be allowed."""
        if not names:
            return set()
        ctx = self._request_context(context)
        if ctx is None:
            self._engine.record_refusal()
            return set()
        verdicts = await self._engine.evaluate_each(
            [NormalizedToolCall(name=name) for name in names], request_context=ctx
        )
        return {
            name
            for name, verdict in zip(names, verdicts, strict=True)
            if is_allowed_gateway(verdict)
        }

    def _request_context(self, context: MiddlewareContext[Any]) -> dict[str, Any] | None:
        """Host context + resolved subject + server label; ``None`` when no subject."""
        ctx: dict[str, Any] = dict(current_request_context.get() or {})
        subject = self._resolve_subject(ctx)
        if subject is None:
            return None
        # Injected explicitly: the mapper reads request_context["subject"] first, so a
        # validated token outranks any ambient or host-provided value.
        ctx["subject"] = subject
        if self._server_label is not None:
            ctx[MCP_SERVER_LABEL_KEY] = self._server_label
        elif MCP_SERVER_LABEL_KEY not in ctx:
            name = _server_name(context)
            if name is not None:
                ctx[MCP_SERVER_LABEL_KEY] = name
        return ctx

    def _resource_request(
        self, context: MiddlewareContext[mt.ReadResourceRequestParams], ctx: dict[str, Any]
    ) -> EvaluationRequest:
        # The URI is the globally meaningful policy key and is kept verbatim (URIs are
        # case-sensitive, unlike tool names); the server label rides along as a property.
        label = ctx.get(MCP_SERVER_LABEL_KEY)
        return EvaluationRequest(
            subject=ctx["subject"],
            action=Action(name="resource.read"),
            resource=Resource(
                type="mcp_resource",
                id=str(context.message.uri),
                properties={"server": label} if isinstance(label, str) else {},
            ),
            context=request_context_attrs(ctx),
        )

    def _prompt_request(
        self, context: MiddlewareContext[mt.GetPromptRequestParams], ctx: dict[str, Any]
    ) -> EvaluationRequest | None:
        # The prompt name is kept VERBATIM, like resource URIs: FastMCP registers case-
        # and whitespace-variant prompts as DISTINCT components, so folding them onto one
        # policy key would let a single ALLOW cover both (which is why mcp_resource_id,
        # which trims segments, is not used for the name). Prompt arguments are not
        # forwarded in v1. A name that is empty or contains "/" cannot form an
        # unambiguous key — refuse.
        label = ctx.get(MCP_SERVER_LABEL_KEY)
        if not isinstance(label, str) or not label.strip() or "/" in label.strip():
            logger.warning("apparitor: no usable server label for prompt authorization; refusing")
            return None
        name = context.message.name
        if not name.strip() or "/" in name:
            logger.warning("apparitor: unusable prompt name for authorization; refusing")
            return None
        return EvaluationRequest(
            subject=ctx["subject"],
            action=Action(name="prompt.get"),
            resource=Resource(
                type="mcp_prompt",
                id=f"{label.strip()}/{name}",
            ),
            context=request_context_attrs(ctx),
        )

    def _resolve_subject(self, request_context: dict[str, Any]) -> Subject | None:
        token = get_access_token()
        if token is not None:
            sub = (token.claims or {}).get(self._subject_claim)
            if isinstance(sub, str) and sub.strip():
                return Subject(
                    type=self._subject_type,
                    id=sub,
                    properties={"client_id": token.client_id, "scopes": list(token.scopes)},
                )
            client_id = token.client_id
            if self._allow_workload_subject and isinstance(client_id, str) and client_id.strip():
                # A verified client-credentials token: a machine principal with its own
                # subject type, so user-keyed policies can never match it. client_id is
                # repeated as a property for symmetry with user subjects (one policy
                # attribute works across both).
                return Subject(
                    type="workload",
                    id=client_id,
                    properties={"client_id": client_id, "scopes": list(token.scopes)},
                )
            # A verified token without a usable subject claim refuses rather than silently
            # downgrading to a fallback (opt in to workload identities explicitly).
            logger.warning(
                "apparitor: access token has no usable %r claim; refusing (set"
                " allow_workload_subject=True to authorize client-credentials tokens"
                " as workload subjects)",
                self._subject_claim,
            )
            return None
        host_provided = request_scoped_subject(request_context)
        if host_provided is not None:
            return host_provided
        if self._allow_static_subject and self._config.agent_id is not None:
            return Subject(type=self._config.subject_type, id=self._config.agent_id)
        logger.warning(
            "apparitor: no authenticated subject for MCP request; refusing (configure"
            " server auth, or opt in to allow_static_subject for local/stdio use)"
        )
        return None

    async def aclose(self) -> None:
        """Release the underlying PDP client (FastMCP never closes middleware itself).

        Only closes a client this adapter created; a bring-your-own ``http_client`` is left
        for the caller to manage.
        """
        await self._engine.aclose()

    async def __aenter__(self) -> FastMCPAuthorizationMiddleware:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


def _listed_name(tool: Any) -> str:
    """The client-visible (mount-prefixed) tool name, as ``on_call_tool`` will receive it.

    The supported FastMCP lines disagree under composition: 2.14 keeps ``Tool.name``
    unprefixed and puts the prefixed name in ``Tool.key``, while 3.x and 4.x prefix
    ``Tool.name`` (their ``key`` is a ``tool:...@`` component locator). Using the wrong one
    would make the listing filter and the call gate evaluate different policy keys.
    """
    key = getattr(tool, "key", None)
    if isinstance(key, str) and key and ":" not in key:
        return key
    name: str = tool.name
    return name


def _server_name(context: MiddlewareContext[Any]) -> str | None:
    """The name of the FastMCP server handling the call, or ``None`` if unresolvable."""
    fastmcp_ctx = context.fastmcp_context
    server = getattr(fastmcp_ctx, "fastmcp", None) if fastmcp_ctx is not None else None
    name = getattr(server, "name", None)
    if isinstance(name, str) and name.strip():
        return name
    return None


__all__ = ["FastMCPAuthorizationMiddleware"]
