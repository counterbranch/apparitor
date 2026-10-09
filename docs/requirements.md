# Technical Requirements & Design Decisions

This document specifies apparitor's shipping authorization pipeline: the AuthZEN evaluation
core and its LlamaFirewall scanner integration. It is the authoritative design reference
that the implementation satisfies; broader firewall and policy-engine support is tracked in
[`ROADMAP.md`](../ROADMAP.md). It was hardened by a six-discipline principal review
(AI/agent, solution architecture, software, security, DevOps, QA).

## 1. Goal & scope

Provide a LlamaFirewall `Scanner` that authorizes an agent's tool calls against any
AuthZEN 1.0 PDP and returns `ALLOW` / `BLOCK` / `HUMAN_IN_THE_LOOP_REQUIRED`.

**In scope:** the scanner, the AuthZEN client + models, tool-call extraction, mapping,
caching, configuration, examples for OpenFGA / Cedar / OPA / a mock PDP (Cerbos and
Amazon Verified Permissions also work and may be added), the NeMo Guardrails rail
(`apparitor.nemo`), the FastMCP server middleware (`apparitor.fastmcp`), and the A2A
executor (`apparitor.a2a`), LiteLLM Proxy guardrail (`apparitor.litellm`), and
optional privacy-bounded evidence sink (`apparitor.audit`).

**Out of scope** (documented, deferred): control-plane decision-log emission, OPA
bundles, Microsoft Agent Governance rails, natural-language policy authoring.

## 2. Interfaces we build against

### 2.1 LlamaFirewall `Scanner` (Meta PurpleLlama)

- `class Scanner(ABC)`, `__init__(self, scanner_name: str, block_threshold: float = 1.0)`.
- `@abstractmethod async def scan(self, message: Message, past_trace: Trace | None = None) -> ScanResult`.
  The sync `LlamaFirewall.scan()` wraps this in `asyncio.run`; `scan_async()` is native.
- `Message`: `role: Role`, `content: str`, `tool_calls: list[dict] | None`, **not
  normalised**. Only `AssistantMessage` carries `tool_calls`.
- `ScanResult(decision: ScanDecision, reason: str, score: float, status: ScanStatus = SUCCESS)`.
- `ScanDecision ∈ {ALLOW, HUMAN_IN_THE_LOOP_REQUIRED, BLOCK}`;
  `ScanStatus ∈ {SUCCESS, ERROR, SKIPPED}`.
- **Registration:** prefer passing a configured instance into the role→scanner
  `Configuration` map (the `@register_llamafirewall_scanner` decorator instantiates
  arg-less and can't carry our config). **Bind to the `ASSISTANT` role**: this is a
  *pre-execution* gate; binding to the tool-output role would authorize after the call
  already ran.

### 2.2 AuthZEN 1.0 (OpenID, finalized 2026)

- Single: `POST /access/v1/evaluation` → body `{subject, action, resource, context?}`,
  response `{decision: bool, context?}`.
- Batch: `POST /access/v1/evaluations` → top-level tuple as defaults + `evaluations[]`
  + `options.evaluations_semantic ∈ {execute_all, deny_on_first_deny, permit_on_first_permit}`,
  response `{evaluations: [{decision, context?}]}`.

## 3. Resolved design decisions

### 3.1 LlamaFirewall dependency: hard, never shimmed
Only `scanner.py` imports LlamaFirewall, and it imports the **real**
`Scanner`/`ScanResult`/`ScanDecision`/`Message` types (no re-declared stub types: stub
enums would break `is`/`isinstance` identity when the LlamaFirewall runtime consumes our
`ScanResult`). `llamafirewall` is an **optional extra** but is required for the scanner
import path; importing `scanner.py` without it raises `MissingDependencyError`. Every
other module is LlamaFirewall-free and standalone-importable. Type-only references use
`if TYPE_CHECKING:`.

### 3.2 Tool-call extraction is provider-aware
`Message.tool_calls` shape is framework-specific:
- OpenAI: `{"function": {"name", "arguments": "<JSON string>"}}`; `arguments` is a JSON
  **string** (`json.loads` it).
- Anthropic: `{"type": "tool_use", "name", "input": {…}}`.
- LangChain: `{"name", "args": {…}}`.

A pluggable `ToolCallAdapter` detects the shape and normalises to
`NormalizedToolCall{name, arguments: dict, id}`. **Every** call in `tool_calls` is
authorized (not just `[0]`: smuggling a malicious call beside a benign one must not
bypass). There is **no** regex-from-`content` path (model content is attacker-influenced).

### 3.3 Mapping: one seam
A single `ToolCallMapper.map(tool_call, request_context) -> EvaluationRequest | None`
protocol (subject/resource/context shaping share the same request context, so three
protocols would be over-factored). The default mapper:
- **subject**: request-scoped, read from the `current_subject` `ContextVar` (the end
  user the agent acts for), falling back to the configured static agent subject. **Never**
  derived from message content/arguments.
- **action**: `config.action_name` (default `tool_call.execute`).
- **resource**: `{type: "tool", id: <normalised tool name>}`. Default type is `tool`,
  **not** `mcp_tool` (tool calls at the LLM layer rarely carry MCP provenance). A
  non-default `MCPResourceMapper` keys `resource.id = "<server>/<tool>"` for genuine MCP
  deployments. Tool names are normalised (case/namespace) to prevent `Tool` vs `tool`
  evasion.
- **arguments** → `resource.properties.arguments` (so PDPs can write ABAC like
  *"deny `delete_file` where path startswith `/etc`"*), size-capped and redactable, and
  documented to policy authors as **untrusted** model output.
- **context** → `conversation_id`, `user_id`, a correlation nonce.

### 3.4 Async-native, safe sync
`scan()` is `await`-only end-to-end and uses only `httpx.AsyncClient`. No `asyncio.run`
anywhere in our code (it raises inside an already-running loop, the common agent case).
A synchronous client variant, if provided, uses a real `httpx.Client`; if a running loop
is detected on a sync path, raise a clear error (never `nest_asyncio`). The scanner owns
**one long-lived pooled** `AsyncClient` reused across calls, closed via `aclose()`.

### 3.5 Decision → `ScanResult`
`decision == true → ALLOW (score 0.0)`; `decision == false → BLOCK (score 1.0)`. A binary
PDP makes `block_threshold` inert (documented). An optional `review_predicate` over the
PDP response `context` may only **escalate** along the lattice `BLOCK > HUMAN > ALLOW`
(implementation asserts output ≥ base decision, so it can never downgrade a deny using
PDP-supplied advisory fields).

### 3.6 Errors → decision (security-critical): **no global fail-open**
`on_error ∈ {deny (default), human_review}`. There is no allow-on-failure option; an
authorization gate that can be configured to fail open is not a gate. Resolution is
per error class:

| Error class | Trigger | Default verdict | Retry? | `status` |
| --- | --- | --- | --- | --- |
| Transport | connection refused / DNS / TLS failure | `on_error` (BLOCK) | yes (bounded) | `ERROR` |
| Timeout | exceeded read timeout / budget | `on_error` (BLOCK) | yes (within budget) | `ERROR` |
| Server `5xx` | 500/502/503/504 | `on_error` (BLOCK) | yes (429/502/503/504) | `ERROR` |
| Client `4xx` | 400/401/403/422 (our bug/misconfig) | **BLOCK, loudly** | no | `ERROR` |
| Malformed `2xx` | missing/non-bool `decision` | `on_error` (BLOCK) | no | `ERROR` |

A missing `decision` is an error, **never** a falsy allow. Any verdict produced via the
error path sets `status = ERROR`, so "policy denied" is distinguishable from "PDP down".

### 3.7 Transport, retries, SSRF
- Hand-rolled bounded retry (exponential backoff + jitter), **only** on `429`/`5xx`
  (502/503/504) and transport errors, never `4xx`, never a valid deny. (httpx
  transport-level retries cover connection failures only, not `5xx`/`429`; no `tenacity`.)
- Explicit `httpx.Timeout(connect, read, write, pool)`; retries live **within** the total
  `request_budget_s` (not additive).
- **TLS `verify=True`** by default. `pdp_url` is operator config only (never derived from
  a message) and must be HTTPS; private/RFC1918/link-local/`169.254.169.254` hosts are
  rejected unless `allow_insecure_pdp` is set (local-dev only). Otherwise an injected URL
  is full SSRF + bypass.
- **Bring-your-own `httpx` client**: callers may pass a pre-configured `AsyncClient` to
  own bearer/mTLS auth, TLS roots, proxies and timeouts. Secrets are never read from or
  written to message content/logs.

### 3.8 Batch evaluation
One tool call → `/evaluation`; N > 1 → `/evaluations`. Default semantic **`execute_all`**
(retains per-tool decisions for audit). Aggregation: the message is `ALLOW` **iff every**
entry is allowed; any deny **or any un-evaluated entry** → `BLOCK`. Map results to calls
by position only under `execute_all`; tolerate short-circuited arrays under
`deny_on_first_deny`. Authorization is point-in-time: bind the ALLOW to the exact
argument fingerprint that executes; if arguments mutate before execution, the ALLOW is
void (TOCTOU).

### 3.9 Caching (opt-in, OFF by default)
When enabled: cache **ALLOW only**; short default TTL (`cache_ttl_s`, ~60s) with a hard
ceiling (`cache_max_ttl_s`, ~300s); any PDP-suggested TTL is clamped **down**. Key =
SHA-256 of canonical, sorted, type-tagged JSON over the **full** tuple, including a hash
of `resource.properties.arguments` (so `delete_file(/tmp/x)` cannot serve a cached ALLOW
for `delete_file(/etc/passwd)`); never string concatenation, never a "context subset".
**Never** cache error/timeout/HITL outcomes (would poison the cache). Provide a flush hook
and the `cache_enabled=False` kill switch for incident response. Concurrency model and
in-flight coalescing are pinned in [architecture.md](architecture.md).

### 3.10 Configuration & observability
`ScannerConfig` is a pydantic v2 model (validation, `HttpUrl`, enum coercion, bounds).
Happy-path kwargs (`pdp_url`) populate it so `AuthZENScanner(pdp_url=...)` works in ≤10
lines. Structured decision logs carry tool name + decision + subject id + correlation id +
an **argument fingerprint** (not raw arguments/PII by default; verbose mode is opt-in and
flagged sensitive). A redaction layer guarantees auth tokens never appear in logs (asserted
by test). The returned `reason` stays generic (`"blocked by authorization policy"`);
detailed why-denied goes to operator logs only. Emit a decision-latency histogram and a
cache-hit counter from day one.

## 4. Pinned semantics (resolve the QA-flagged ambiguities)

1. **No actionable call.** `tool_calls is None` (or empty) → nothing to authorize →
   `ScanStatus.SKIPPED` (decision `ALLOW`, the scanner abstains). `tool_calls` present but
   a member is **unparseable** by every adapter → `BLOCK` (never `SKIPPED`): an attacker
   malforming a call must not slip through.
2. **`status` on error-path verdicts** → `ScanStatus.ERROR` (even when the verdict is a
   policy-shaped `BLOCK`).
3. **Retry policy per error class** → table in §3.6.
4. **`review_predicate` vs a `false` decision** → deny wins; the predicate may only
   escalate (§3.5).
5. **Batch aggregation vs `evaluations_semantic`** → ALL-allow required (§3.8); covered by a
   parametrized decision table in the test suite.

## 5. Configuration reference (`ScannerConfig`)

See [`config.py`](../src/apparitor/config.py). Secure defaults: `on_error=deny`,
`verify_tls=True`, `allow_insecure_pdp=False`, `cache_enabled=False`,
`request_budget_s=2.0`, `max_retries=2`. The batch semantic is not a `ScannerConfig`
field; it lives on the wire model `EvaluationsOptions.evaluations_semantic` (default
`execute_all`).

## 6. Acceptance criteria

- A denied tool call → `BLOCK`; an authorized one → `ALLOW`; PDP unreachable →
  `BLOCK` or `HUMAN_IN_THE_LOOP` per `on_error`, with `status=ERROR`.
- Provider shapes (OpenAI/Anthropic/LangChain) all normalise correctly; multi-call messages
  are fully authorized; unparseable calls fail closed.
- Subject is never derived from message content; `pdp_url` SSRF guard enforced; tokens never
  logged (asserted).
- Conformance against the vendored OpenID AuthZEN interop decisions dataset.
- ≥90% line+branch coverage on the LlamaFirewall-free modules; golden request-body tests.
