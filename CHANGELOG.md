# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- LiteLLM Proxy custom guardrail using authenticated key-owner identity and fail-closed
  checks for offered tools and returned tool calls, plus a resolved MCP execution guardrail.
  Streaming and unresolved MCP requests are refused.
- Optional bounded JSONL authorization evidence, separate host-observed execution
  outcomes and operational summaries; the existing text log grammar is unchanged.
- Trace and identity provenance, structured reason codes, keyed argument fingerprints,
  and collection-gap observations. Durable SQLite outbox with bounded retries and receipts.
- Local Observe reference with tenant-bound ingestion, search, timelines, operational
  alerts and a dashboard; an in-process delivery demo exercises lost acknowledgements.
- Conventional API example with explicit trusted identity resolution and protected reads.
- `RELEASING.md` runbook, and a release-pipeline guard that fails a tagged build when the
  pushed tag does not match `__version__` (`.github/workflows/release.yml`).

### Changed
- Repository and publisher documentation uses `counterbranch/apparitor` after the transfer.
- Cedar extra targets the locally tested 4.12 line; EU and state-law evidence mappings
  distinguish current law, proposed measures and evidence not collected by this library.
- Observe serializes its shared SQLite connection; database and WAL/SHM files are secured
  to `0600` in owned directories without group/world write access.
- Dependency updates include setup-uv 10.2.0 and cyclonedx-bom 7.5.0; Dependabot also tracks
  API and Observe example requirements.
- Install instructions now point at PyPI (`pip install apparitor`) now that the `0.1.x`
  line is published, replacing the previous install-from-source guidance.
- **NeMo Guardrails rail migrated to NeMo's `RailOutcome` contract (breaking; requires
  `nemoguardrails>=0.24`).** NeMo 0.24 removed `@action(output_mapping=...)`, which the
  adapter relied on for its fail-closed allow/block mapping. `NeMoAuthorizationRails.action`
  now returns a `RailOutcome`: `allow()` only for a clean `ALLOW` / `SKIP`, `block()` for
  `BLOCK`, `HUMAN_REVIEW` and any error verdict. The verdict detail
  (`tool_authorization_verdict` / `_status` / `_reason` / `_score`) moves from
  `ActionResult.context_updates` to `RailOutcome.metadata`, and Colang flows change from
  `$allowed = execute authorize_tool_calls(...)` / `if not $allowed` to
  `$result = execute authorize_tool_calls(...)` / `if $result.is_blocked` (see the module
  docstring). The `[nemo]` extra is now `nemoguardrails>=0.24,<0.25`.
- **FastMCP middleware supports fastmcp 4.x.** The `[fastmcp]` extra now accepts
  `fastmcp>=2.14,!=3.0.*,<5`, and the `fastmcp` / `gateway-demo` CI jobs exercise 2.14, 3.x
  and 4.x. No adapter change was needed: the middleware hooks, `get_access_token` and the
  `ToolError` / `ResourceError` / `PromptError` surfaces are unchanged in 4.0.

### Removed
- `apparitor.nemo.authorization_blocks`: NeMo 0.24 dropped the `output_mapping` hook it
  existed for; the fail-closed allow/block mapping now lives in the returned `RailOutcome`.

## [0.1.1] - 2026-06-16

### Added
- **`request_context_scope(context)` context manager** (`apparitor.mapping`, exported from
  `apparitor`). Mirrors `subject_scope`: binds `current_request_context` for the duration
  of the `with` block and resets it in `finally`, so a host that forgets to reset cannot
  leak a prior request's injected context into a later request on a reused task/loop. This
  is now the preferred pattern over calling `.set()/.reset()` directly (documented in
  `docs/setup.md`).
- **Security posture & assurance document** (`docs/security-review.md`): standing
  invariants, threat-model coverage, test citations, known limitations, and re-review
  triggers. A continuously scannable baseline.

### Security
- **PDP response parsing now rejects duplicate JSON keys (§3.6), failing closed with
  `MalformedPDPResponseError`.** An `object_pairs_hook` in the new `_strict_json` helper
  raises `MalformedPDPResponseError` on any duplicate key within a JSON object, closing a
  response-validation gap at the PDP trust boundary. The fix applies to both the AuthZEN
  transport and the OPA backend. Sibling objects in a batch response (multiple `"decision"`
  fields in distinct array entries) are correctly not flagged; the check is per-object.
- **Error-path `VerdictResult.reason` is now always a generic string (§3.10).** All
  error-path verdicts use the fixed `_DENY_REASON` constant, ensuring internal detail
  (exception text, transport state) is never exposed to callers. Exception detail continues
  to appear in operator logs for diagnostics. The fix also adds log lines on early-return
  paths that previously had none (unparseable tool call, 4xx client error).
- **`asyncio.CancelledError` is now recorded in metrics before re-propagating.** A
  dedicated `except asyncio.CancelledError` clause in `_evaluate_guarded` records a
  `block/error` decision metric and immediately re-raises, preserving
  structured-concurrency invariants. The public `evaluate_normalized` and
  `evaluate_requests` docstrings note that `CancelledError` propagates and callers must
  treat an unfinished scan as non-authorized.
- **Cedar `_entity_uid` hardened to reject backslash and control characters.** The
  rejection is now explicit at the validation seam (covering double-quote, backslash, and
  control characters), so invalid identifiers are caught before Cedar processes them. The
  engine already failed closed on a Cedar parse error (NoDecision becomes BLOCK); this makes
  the boundary explicit.
- **`.env` added to `.gitignore`; `llamafirewall` extra capped at `<1`.** Prevents
  accidental credential commits and pins the audited major version of the ML stack.

### Changed
- **`AuthZENConfigError` now also inherits `ValueError` for backward compatibility.**
  Adapter constructors previously raised plain `ValueError` for misconfiguration (missing
  PDP URL, reserved subject type, invalid label, now all four adapters, including the
  scanner). Code catching `except ValueError` still catches these; code that was already
  catching `except AuthZENConfigError` is unaffected. Pre-1.0 decision: keeping the mixin
  avoids a breaking change for callers that only imported the public error hierarchy after
  the fact. Update existing `except ValueError` handlers that handle only configuration
  errors to catch `AuthZENConfigError` instead for precision. `build_engine` now also
  rejects providing both `pdp_url` and `config` simultaneously (previously config silently
  won; now a `AuthZENConfigError` is raised).
- **Inline/gateway SKIP semantics and batch-item merge logic unified across all adapters.**
  `is_allowed_inline`, `is_allowed_gateway`, `record_pre_engine_refusal`, and
  `DUAL_PRINCIPAL_CACHE_WARNING` are shared helpers in `apparitor.decision` (lowest-common
  import, engine-free and host-SDK-free to avoid import cycles); their divergent SKIP
  behaviour and the `is not None` batch-item merge semantics are pinned by tests.

## [0.1.0] - 2026-06-11

### Added
- **Audit-log schema frozen as a stability contract (`docs/audit-log.md`).** Logger,
  levels, C1/C2/C3 line grammar (format strings, field tables, rendered examples),
  fingerprint derivation, parsing guidance, timestamp/clock requirements, an EU
  regulatory mapping (AI Act record-keeping and retention, GDPR handling, transfer
  routing), and stability policy. Pinned by
  `tests/unit/test_log_contract.py`. A failure there is a breaking log-schema change
  requiring a CHANGELOG "Update log parsers" entry and a version bump.
- **Runnable MCP authorization-gateway example (`examples/gateway/`).** A FastMCP proxy
  fronting an unmodifiable upstream, middleware enforcing at the chokepoint: denied calls
  proven never to reach the upstream, listing filtered to hide what the subject may not
  call. Exercised on both supported fastmcp lines by the `gateway-demo` CI job.
- **Runnable scenario walk-through (`examples/scenarios/`).** Dependency-free (core install
  only) self-asserting script over the mock PDP covering seven scenarios: allow, deny
  (2-part deny key), unparseable input fails closed, PDP unreachable with `on_error=deny`,
  PDP unreachable with `on_error=human_review`, batch all-or-nothing aggregation, and
  dual-principal (user AND agent boundary) evaluation. Gated in CI by the `scenarios` job.
  Also: the mock PDP now supports a subject-scoped **3-part deny form**
  (`"<subject_id>:<action>:<resource_id>"`) in addition to the existing 2-part form.
- **Dual-principal evaluation (`DualPrincipalMapper`).** Emits two requests per tool
  call (the end user's grant and the agent's own permission boundary), ANDed by the
  engine's all-allow-or-block aggregation, so an agent can never exercise a permission
  its boundary denies even when the human holds it. The user leg is request-scoped only
  (no `agent_id` fallback, which would collapse the AND); either principal unresolvable
  fails closed; `"workload"` stays reserved. Works via the `mapper=` seam in the scanner,
  the NeMo rail and the FastMCP middleware (tools + listing). Note: dual calls always
  evaluate as a batch, so the opt-in ALLOW cache is not consulted.
- **Dual-principal boundary for adapter-shaped paths (closes
  [#39](https://github.com/jhawlwut/apparitor/issues/39)).** `A2AAuthorizationExecutor`
  and `FastMCPAuthorizationMiddleware` now accept a `boundary_subject` constructor parameter.
  When set, every invocation (A2A) or every `resources/read` / `prompts/get` request (FastMCP)
  is evaluated as a two-request batch (the resolved caller leg AND the boundary leg) using
  the same AND/all-allow-or-block semantics as `DualPrincipalMapper`. For FastMCP,
  `boundary_subject` covers the resource/prompt adapter paths only; use
  `mapper=DualPrincipalMapper(config)` for `tools/call` and listing. A full deployment sets
  both. The same fail-closed guards apply: `"workload"` boundary rejected at construction,
  collapse (boundary == caller) refused before any PDP call, cache warning emitted when
  `cache_enabled=True`. Shared helper `build_boundary_leg` in `apparitor.mapping` (exported
  from the package) powers both adapters.
- `ToolCallMapper.map()` may now return a **sequence** of requests that must all be
  allowed (backward compatible; `None`/empty sequence abstains, since an empty group can
  never read as an allow, on either the aggregate or the per-item path).
- **A2A agent-executor enforcement point (`apparitor.a2a`, optional `[a2a]` extra).**
  `A2AAuthorizationExecutor` wraps a deployment's `AgentExecutor` and authorizes every
  agent-to-agent invocation before it runs (action `agent.invoke`; resource
  `{type: "a2a_agent", id: <agent_label>}`, or `a2a_skill` with a `"<agent>/<skill>"` key
  via the `skill_resolver` hook; segments validated, skill kept verbatim). The subject is
  the server's **authenticated peer** (`Subject(type="agent", id=<user_name>)` by
  default), falling back to a subject injected per request via
  `ServerCallContext.state["subject"]` and then the opt-in static `agent_id`. An
  unauthenticated caller is refused, and ambient contextvars are deliberately ignored
  (the SDK's detached producer task snapshots them, so they go stale across turns). The request's A2A `tenant` is forwarded in the
  AuthZEN context for multi-tenant policies (a caller-supplied claim for policies to
  cross-check, not proof). Verdicts map fail-closed: only a clean
  `ALLOW` reaches the wrapped executor; everything else raises a deliberately generic A2A
  error (the rich reason stays in the operator log). `cancel` passes through ungated in
  v1 (documented). Built on `AuthorizationEngine.evaluate_requests`, no core changes.
- **Complete MCP enforcement scope for the FastMCP middleware** (closes
  [#32](https://github.com/jhawlwut/apparitor/issues/32),
  [#33](https://github.com/jhawlwut/apparitor/issues/33),
  [#34](https://github.com/jhawlwut/apparitor/issues/34)):
  - `resources/read` and `prompts/get` are now **gated by default** (actions
    `resource.read` / `prompt.get`; resource ids: the URI verbatim for resources with the
    server label as a property, `"<server>/<prompt>"` for prompts), with the same subject
    chain, generic refusals (`ResourceError`/`PromptError`) and fail-closed verdict
    mapping as tool calls; `gate_resources=False` / `gate_prompts=False` opt a hook out.
    **Breaking (pre-alpha):** deployments without resource/prompt policies will see those
    requests denied; write policies or opt out.
  - Opt-in `filter_listings=True` hides tools from `tools/list` whose `tools/call` the
    subject would be denied. One batch PDP round trip, advisory only (`tools/call`
    remains the enforcement invariant), and fail-closed (no subject or any fault hides
    everything).
  - Opt-in `allow_workload_subject=True` authorizes verified client-credentials tokens
    (no `sub` claim) as the distinct `Subject(type="workload", id=<client_id>)`, never
    coerced into a user subject; off by default, such tokens keep refusing. The
    `"workload"` subject type is reserved (the constructor rejects it for claim-derived
    and static subjects). Only `tools/list` is filtered; `resources/list` and
    `prompts/list` still advertise names/URIs even though reads/gets are gated.
- `AuthorizationEngine.evaluate_requests()` (pre-mapped requests, e.g. adapter-shaped
  resource/prompt tuples) and `AuthorizationEngine.evaluate_each()` (positional per-item
  verdicts over one batch round trip, for visibility filtering, fail-closed per item).
- **Three-PEP portability demo (`examples/three-peps/`).** The same vendored Cedar policy
  (`examples/cedar/policies.cedar`, deny-override on `destructive == true`) enforced
  identically at the LlamaFirewall scanner, the NeMo Guardrails rail, and the FastMCP
  middleware over the in-process Cedar backend: no Docker, no network. Self-asserting
  (exits non-zero on any verdict mismatch) and gated in CI by the `three-pep-demo` job,
  which installs all three enforcement-point extras and requires every lane to run.
- **FastMCP server-middleware enforcement point (`apparitor.fastmcp`, optional `[fastmcp]`
  extra).** `FastMCPAuthorizationMiddleware` authorizes every MCP `tools/call` server-side,
  before the tool executes, over the same `AuthorizationEngine` as the LlamaFirewall scanner
  and the NeMo rail. The subject comes from the **validated** OAuth access token
  (`claims["sub"]`, configurable) and outranks host-asserted subjects; a token without a
  usable claim refuses, and the static `agent_id` fallback is gated behind an explicit
  `allow_static_subject=True` opt-in (local/stdio only). Verdicts map fail-closed onto MCP:
  only a clean `ALLOW` executes; `BLOCK` / `HUMAN_REVIEW` / mapper abstention / errors raise
  a deliberately generic `ToolError` (the rich reason stays in the operator log). Supports
  fastmcp 2.14 and 3.x (both exercised in CI).
- `AuthorizationEngine.evaluate_normalized()`: a public seam for enforcement points that
  receive tool calls in structured form (no provider-shape adapter detection).
- `MCPResourceMapper` can now resolve its server label per call from
  `request_context[MCP_SERVER_LABEL_KEY]`; the tool segment gets the same case/whitespace
  normalisation as the default mapper, and `mcp_resource_id` rejects embedded `/` (an
  ambiguous policy key), fail-closed.
- `DecisionCache` is bounded: new `cache_max_entries` config (default 10 000, FIFO
  eviction) so per-token subject cardinality cannot grow the ALLOW cache without limit.
- **Docker-free OpenFGA integration backend (linux/amd64).** Set `APPARITOR_OPENFGA_NATIVE=1` to run the
  OpenFGA E2E against a pinned, **SHA-256-verified** OpenFGA release binary launched directly
  (only `github.com` egress needed) instead of a container, so the real-PDP test works where
  the Docker registry is unreachable. Same vendored model + tuples and assertions; a
  `workflow_dispatch` `integration-native` CI job exercises it.
- **Working scan pipeline (M1).** `AuthZENScanner.scan()` authorizes an agent's tool
  calls end-to-end: extract → map → evaluate → decide.
- LlamaFirewall-free `AuthorizationEngine` holding all logic, so the pipeline is fully
  unit-testable without the ML stack. The scanner is a thin adapter that converts the
  verdict to a `ScanResult`.
- `AuthZENClient`: async httpx transport with explicit timeouts, a request budget,
  bounded retries (429/5xx/transport only) with jittered backoff, an SSRF/TLS guard on
  `pdp_url`, bring-your-own-client support, and httpx→typed-error mapping.
- `DefaultToolCallMapper` / `MCPResourceMapper`: request-scoped subject resolution
  (never from model output), argument redaction/size-caps, MCP server-scoped resource ids.
- Opt-in, ALLOW-only TTL `DecisionCache` with a full-tuple SHA-256 key.
- Batch evaluation with all-allow-or-block aggregation; `review_predicate` escalation
  (never downgrade); fail-closed `on_error` (deny / human_review).
- AuthZEN 1.0 pydantic models; provider-aware tool-call adapters (OpenAI / Anthropic /
  LangChain); `ScannerConfig` with secure defaults; exception hierarchy.
- A dependency-free mock AuthZEN PDP for demos/tests.
- Test suite: 90+ unit tests, 98% line+branch coverage on the LlamaFirewall-free
  modules (90% gate enforced), including the security invariants.
- **Real PDP examples (M3).** Runnable OpenFGA example (native, experimental AuthZEN API;
  vendored model + relationship tuples) and Cedar example (policy-as-code behind a local
  AuthZEN → Cedar gateway running the official Cedar CLI), each with a `smoke.sh` and a
  Docker-gated `testcontainers` integration test that skips when no daemon is present.
- `integration` optional-dependency group (`testcontainers`) and a `workflow_dispatch`
  CI job that runs the integration suite.
- **Observability (M2).** A dependency-free metrics sink (`MetricsSink` protocol with a
  default `InMemoryMetrics` and a `NoopMetrics` opt-out): a decision-latency histogram and
  a cache-hit/miss counter, surfaced on the engine and scanner. Structured audit logs now
  carry the verdict, status, subject (decision principal), correlation id, and an argument
  *fingerprint*; raw arguments and tokens are never logged (arguments are fingerprinted).
- **AuthZEN 1.0 wire-conformance suite** (`tests/conformance/`): vendored canonical
  request/response payloads driven through the models and client to prove wire
  compatibility (request shapes, response decisions, batch aggregation, and malformed
  responses failing closed).

### Changed

- **Audit-log message prefixes normalized `authzen` → `apparitor`** to match the logger
  name and project name. Field names and grammar are unchanged. **Update log parsers**
  anchoring on the old `authzen decision`, `authzen batch`, or `authzen per-item`
  prefixes: replace with `apparitor decision`, `apparitor batch`,
  `apparitor per-item`.
- The structured decision log's resource-id field is now `resources=` (was `tools=`).
  It can carry resource URIs and prompt keys, not just tool names. Update log parsers.
- The structured decision log now records **every distinct principal** as `subjects=`
  (was `subject=` with only the first leg). Under dual-principal evaluation the audit
  trail must name both the user and the agent, and `resources=` / `fingerprints=`
  carry one entry per evaluation request, so dual legs appear twice. Update log parsers.
- `DefaultToolCallMapper.map()`'s return annotation is widened to the full
  `ToolCallMapper` union; a typed subclass that delegates to `super().map()` must
  accept the widened return (runtime behaviour of the default mapper is unchanged).
- **Renamed to `apparitor` and repositioned.** The project is now a vendor-neutral
  authorization layer that aggregates policy engines (AuthZEN, Cedar, OpenFGA, Rego) across
  agentic firewalls (LlamaFirewall today; NeMo Guardrails planned), rather than an
  AuthZEN-scanner-for-LlamaFirewall only. The Python import package and PyPI distribution
  are now **`apparitor`** (was `authzen_llamafirewall` / `authzen-llamafirewall-scanner`):
  `from apparitor import AuthZENScanner`. Breaking import change, acceptable pre-alpha, no
  published release affected. Public API names (`AuthZENScanner`, `AuthorizationEngine`, …)
  are unchanged.
- **Spec fix:** the batch options field is now `evaluations_semantic` (plural), matching
  AuthZEN 1.0; it was previously serialised as `evaluation_semantic`. Renames
  `EvaluationsOptions.evaluation_semantic` → `evaluations_semantic` (pre-alpha, breaking).
- `DefaultToolCallMapper._resource` takes the request context (so `MCPResourceMapper` can
  resolve a per-call server label). A custom mapper subclass overriding the protected
  `_resource` must adopt the new signature; the public `ToolCallMapper.map` contract is
  unchanged.

## [0.0.1a0]
- Initial pre-alpha scaffold.
