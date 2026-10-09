"""NeMo Guardrails rail adapter (thin adapter over :class:`AuthorizationEngine`).

This is the **only** module that imports NeMo Guardrails. The import is guarded so that
importing it without ``nemoguardrails`` installed yields a clear
:class:`~apparitor.errors.MissingDependencyError` rather than an opaque ``ImportError``.

It binds the firewall-free :class:`AuthorizationEngine` behind a NeMo **custom action** so a
NeMo-guarded agent gets the *identical* authorization check the LlamaFirewall scanner
provides — same engine, same mapper, same fail-closed semantics, same request-scoped subject
resolution (``current_subject`` / ``current_request_context`` / ``config.agent_id``). Only the
boundary differs: the verdict is mapped onto NeMo's allow / block(refuse) model.

The action returns a NeMo ``RailOutcome``, the engine-neutral rail verdict NeMo's runtimes gate
on. The mapping is fail-closed:
only ``ALLOW`` / ``SKIP`` with a non-error status becomes ``RailOutcome.allow()``; ``BLOCK``,
``HUMAN_REVIEW`` (refused; escalation is a host concern) and any ``status=ERROR`` become
``RailOutcome.block()``. The richer verdict (verdict / status / reason / score) rides along in
``RailOutcome.metadata`` so a host can build a refusal message or an escalation flow on top of
it; the decision itself is never derived from the metadata.

Register the action on an ``LLMRails`` (before generating), then reference the flow as a rail.
NeMo has no built-in "tool calls" context key, so the host sets the agent's proposed tool calls
in the rails context under ``tool_calls`` (for example via a ``{"role": "context", ...}``
message); the action reads them from there and SKIPs (allows) a turn that carries none. How
you obtain them depends on your agent integration. Wiring::

    from nemoguardrails import LLMRails, RailsConfig

    rails = LLMRails(RailsConfig.from_path("config"))
    NeMoAuthorizationRails(pdp_url="https://pdp.internal").register(rails)

``config/config.yml`` activates the flow as a rail::

    rails:
      input:
        flows:
          - authorize tool calls

``config/rails.co`` refuses a denied tool call (the canonical ``self check input`` shape)::

    define bot refuse to authorize tool call
      "I can't authorize that action."

    define flow authorize tool calls
      $result = execute authorize_tool_calls()
      if $result.is_blocked
        bot refuse to authorize tool call
        stop

Passing the calls explicitly (``execute authorize_tool_calls(tool_calls=$tool_calls)``) works
too, but then ``$tool_calls`` must be set on every turn: Colang 1 hands an unset variable to
the action as the literal string ``"$tool_calls"``, which fails the check (closed) as a NeMo
internal error rather than SKIPping.

A ``HUMAN_REVIEW`` verdict refuses too (NeMo has no native human-in-the-loop pause); the
verdict is surfaced in the outcome's metadata, so a host builds escalation by branching on it,
e.g. ``if $result.metadata["tool_authorization_verdict"] == "human_review"``.

The host sets the trusted subject/context out-of-band before invoking the rails — never from
model or tool output (a confused-deputy hazard) — exactly as with the scanner::

    with subject_scope(Subject(type="user", id="alice@acme.com")):
        await rails.generate_async(messages=...)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from .config import ScannerConfig
from .decision import VerdictResult, is_allowed_inline
from .engine import ReviewPredicate, build_engine, resolve_config
from .errors import MissingDependencyError
from .mapping import current_request_context

try:  # pragma: no cover - exercised via import-guard tests
    from nemoguardrails.actions import action
    from nemoguardrails.actions.rail_outcome import RailOutcome
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.nemo requires NeMo Guardrails. Install it with:\n"
        "    pip install 'apparitor[nemo]'"
    ) from exc

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    import httpx
    from nemoguardrails import LLMRails

    from .audit import AuditSink
    from .mapping import ToolCallMapper
    from .metrics import MetricsSink


def _outcome(verdict: VerdictResult) -> RailOutcome:
    """Map the engine verdict onto NeMo's rail contract, fail-closed.

    Only a clean ``ALLOW`` / ``SKIP`` allows; a denied, human-review or error verdict blocks.
    The verdict detail is plain-typed metadata for refusal messages and escalation flows.
    """
    metadata = {
        "tool_authorization_verdict": verdict.verdict.value,
        "tool_authorization_status": verdict.status.value,
        "tool_authorization_reason": verdict.reason,
        "tool_authorization_score": verdict.score,
    }
    if is_allowed_inline(verdict):
        return RailOutcome.allow(reason=verdict.reason, metadata=metadata)
    return RailOutcome.block(reason=verdict.reason, metadata=metadata)


def _tool_calls_from_context(context: Mapping[str, Any] | None) -> list[dict[str, Any]] | None:
    """Fall back to ``context["tool_calls"]`` when the flow does not pass them explicitly."""
    if not context:
        return None
    calls = context.get("tool_calls")
    return calls if calls else None


class NeMoAuthorizationRails:
    """Authorizes an agent's tool calls against an AuthZEN PDP from inside NeMo Guardrails.

    Construct it like the scanner — a ``pdp_url`` or a full :class:`ScannerConfig` — then
    :meth:`register` the custom action onto an ``LLMRails`` and reference it from a rail flow
    (see the module docstring). A subject must be resolvable (via ``current_subject`` /
    ``current_request_context`` or ``config.agent_id``) or the authorization fails closed.
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
        action_name: str = "authorize_tool_calls",
    ) -> None:
        self._config = resolve_config(pdp_url, config)
        self._engine = build_engine(
            self._config,
            http_client=http_client,
            mapper=mapper,
            review_predicate=review_predicate,
            metrics=metrics,
            audit_sink=audit_sink,
            audit_fingerprint_key=audit_fingerprint_key,
            audit_integration="nemo",
        )
        self.action_name = action_name
        self._action = self._build_action()

    @property
    def metrics(self) -> MetricsSink:
        """The engine's metrics sink (latency histogram + cache-hit counter)."""
        return self._engine.metrics

    @property
    def action(self) -> Callable[..., Awaitable[RailOutcome]]:
        """The registered NeMo action coroutine (returns a ``RailOutcome``)."""
        return self._action

    def register(self, rails: LLMRails) -> LLMRails:
        """Register the authorization action on ``rails`` and return it (chainable)."""
        rails.register_action(self._action, name=self.action_name)
        return rails

    def _build_action(self) -> Callable[..., Awaitable[RailOutcome]]:
        engine = self._engine

        async def authorize_tool_calls(
            tool_calls: list[dict[str, Any]] | None = None,
            context: Mapping[str, Any] | None = None,
        ) -> RailOutcome:
            verdict = await engine.evaluate_tool_calls(
                tool_calls if tool_calls is not None else _tool_calls_from_context(context),
                request_context=current_request_context.get(),
            )
            return _outcome(verdict)

        # NeMo ships no type stubs, so @action is untyped; apply it as a call (not decorator
        # syntax) and re-assert the type we authored, keeping the function statically typed.
        decorated = action(name=self.action_name)(authorize_tool_calls)
        return cast("Callable[..., Awaitable[RailOutcome]]", decorated)

    async def aclose(self) -> None:
        """Release the underlying PDP client (call on teardown).

        Only closes a client this adapter created; a bring-your-own ``http_client`` is left for
        the caller to manage.
        """
        await self._engine.aclose()

    async def __aenter__(self) -> NeMoAuthorizationRails:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


__all__ = ["NeMoAuthorizationRails"]
