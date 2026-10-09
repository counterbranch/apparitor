"""The LlamaFirewall scanner plugin (thin adapter over :class:`AuthorizationEngine`).

This is the **only** module that imports LlamaFirewall. The import is guarded so that
importing it without ``llamafirewall`` installed yields a clear
:class:`~apparitor.errors.MissingDependencyError` rather than an opaque
``ImportError``. We import LlamaFirewall's real ``Scanner``/``ScanResult``/``ScanDecision``
types directly — never re-declared stubs — so returned objects are identity-compatible
with the LlamaFirewall runtime.

All logic lives in the LlamaFirewall-free :class:`AuthorizationEngine`; this class only
wires configuration and converts the engine's :class:`VerdictResult` into a ``ScanResult``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .config import ScannerConfig
from .decision import Verdict, VerdictResult, VerdictStatus
from .engine import ReviewPredicate, build_engine, resolve_config
from .errors import MissingDependencyError
from .mapping import current_request_context

try:  # pragma: no cover - exercised via import-guard tests
    from llamafirewall import (
        Message,
        ScanDecision,
        Scanner,
        ScanResult,
        ScanStatus,
        Trace,
    )
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "apparitor.scanner requires LlamaFirewall. Install it with:\n"
        "    pip install 'apparitor[llamafirewall]'"
    ) from exc

if TYPE_CHECKING:
    import httpx

    from .audit import AuditSink
    from .mapping import ToolCallMapper
    from .metrics import MetricsSink

_DECISION: dict[Verdict, ScanDecision] = {
    Verdict.ALLOW: ScanDecision.ALLOW,
    Verdict.SKIP: ScanDecision.ALLOW,
    Verdict.HUMAN_REVIEW: ScanDecision.HUMAN_IN_THE_LOOP_REQUIRED,
    Verdict.BLOCK: ScanDecision.BLOCK,
}

_STATUS: dict[VerdictStatus, ScanStatus] = {
    VerdictStatus.SUCCESS: ScanStatus.SUCCESS,
    VerdictStatus.ERROR: ScanStatus.ERROR,
    VerdictStatus.SKIPPED: ScanStatus.SKIPPED,
}


class AuthZENScanner(Scanner):  # type: ignore[misc]  # LlamaFirewall ships no type stubs (Scanner is Any)
    """Evaluates agent tool calls against an AuthZEN PDP.

    Happy path::

        scanner = AuthZENScanner(pdp_url="https://pdp.internal", config=...)
        firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
        result = await firewall.scan_async(message)

    Bind this to the **assistant** role: it is a pre-execution gate, so it must run before
    the tool call is dispatched, not on the tool-output role. A subject must be resolvable
    (via ``current_subject`` or ``config.agent_id``) or the scan fails closed.
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
        scanner_name: str = "AuthZENAuthorizationScanner",
        block_threshold: float = 1.0,
    ) -> None:
        super().__init__(scanner_name, block_threshold)
        self._config = resolve_config(pdp_url, config)
        self._engine = build_engine(
            self._config,
            http_client=http_client,
            mapper=mapper,
            review_predicate=review_predicate,
            metrics=metrics,
            audit_sink=audit_sink,
            audit_fingerprint_key=audit_fingerprint_key,
            audit_integration="scanner",
        )

    @property
    def metrics(self) -> MetricsSink:
        """The engine's metrics sink (latency histogram + cache-hit counter)."""
        return self._engine.metrics

    async def scan(self, message: Message, past_trace: Trace | None = None) -> ScanResult:
        """Authorize the tool call(s) in ``message`` against the PDP."""
        tool_calls = _tool_calls(message)
        verdict = await self._engine.evaluate_tool_calls(
            tool_calls, request_context=current_request_context.get()
        )
        return self._to_scan_result(verdict)

    def _to_scan_result(self, verdict: VerdictResult) -> ScanResult:
        return ScanResult(
            decision=_DECISION[verdict.verdict],
            reason=verdict.reason,
            score=verdict.score,
            status=_STATUS[verdict.status],
        )

    async def aclose(self) -> None:
        """Release the underlying PDP client (call on scanner teardown).

        Only closes a client the scanner created; a bring-your-own ``http_client`` is left
        for the caller to manage.
        """
        await self._engine.aclose()

    async def __aenter__(self) -> AuthZENScanner:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


def _tool_calls(message: Message) -> list[dict[str, Any]] | None:
    raw = getattr(message, "tool_calls", None)
    return raw if raw else None


__all__ = ["AuthZENScanner", "ReviewPredicate", "ScanDecision", "ScanStatus"]
