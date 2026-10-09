# apparitor

[![CI](https://github.com/counterbranch/apparitor/actions/workflows/ci.yml/badge.svg)](https://github.com/counterbranch/apparitor/actions/workflows/ci.yml)
[![pip-audit](https://github.com/counterbranch/apparitor/actions/workflows/pip-audit.yml/badge.svg)](https://github.com/counterbranch/apparitor/actions/workflows/pip-audit.yml)
[![Coverage](https://img.shields.io/badge/core%20coverage-%E2%89%A590%25-brightgreen.svg)](https://github.com/counterbranch/apparitor/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/counterbranch/apparitor?utm_source=oss&utm_medium=github&utm_campaign=counterbranch%2Fapparitor&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)](https://coderabbit.ai)

**Your agents route around the authorization you already run.** apparitor brings them
back under it. Every agent action (an LLM tool call, an MCP request, an agent-to-agent
invocation) is checked against the policy engine you already trust (OpenFGA, Cedar, OPA),
*before* it executes. It answers the question content-safety layers never ask: is this
agent *allowed* to do this? Vendor-neutral, built on the AuthZEN 1.0 interop standard,
Apache-2.0.

## TL;DR

AI agents act through tools, MCP servers, and other agents, and they bypass the
authorization you already run. apparitor puts that authorization back in front of every
agent action. You write no new policy and add no new enforcement layer.

1. **Plug into the agent controls you already run.** apparitor ships an adapter for each,
   so the check runs inside your existing layer:
   - **Meta LlamaFirewall**: authorization scanner
   - **NVIDIA NeMo Guardrails**: authorization rail
   - **FastMCP**: MCP server middleware (subject taken from the validated OAuth token)
   - **A2A**: agent-to-agent executor
   - **LiteLLM Proxy**: model-tool and MCP gateway execution guardrails (unreleased;
     [setup and boundaries](docs/litellm.md))

2. **Decide with the Policy-as-Code engine you already trust.** One integration speaks the
   **AuthZEN 1.0** interop standard, so the decision comes from your engine with no policy
   rewrite: **OPA/Rego**, **Cedar**, **OpenFGA** (experimental), or any AuthZEN PDP such as
   Cerbos, Topaz, or Amazon Verified Permissions. OPA and Cedar also run as native
   in-process backends. A direct OpenFGA backend and managed Amazon Verified Permissions
   are next.

One engine returns one fail-closed verdict (`allow`, `block`, or `human-review`) through
each adapter. It answers the question content scanners skip: is this agent
allowed to do this?

## Get started

apparitor is on PyPI:

```bash
pip install apparitor
```

Then wire it up with the [Quickstart](#quickstart). Each enforcement point is an optional
extra; see [Installation](#installation) for the full matrix.

## The gap

Every safety layer in your stack inspects the *content* of an agent's action: is the
prompt a jailbreak, is the generated code malicious. None asks the question your security
model actually depends on. Is this agent **allowed** to do this, for this user, against
this resource, right now?

The actions that matter most are the ones that look harmless. An agent reading a customer
record is benign text; reading *another tenant's* record is a breach. No content scanner
can tell them apart. The difference isn't in the text, it's in who is acting and what
they're entitled to.

```text
Agent for alice@acme  →  read_records(tenant="globex")
         │
         ▼
   Safety scanning    → "Is this prompt malicious?"             → PASS (benign request)
         │
         ▼
   ??? nothing ???    → "May alice@acme read globex's records?" → NO CHECK
         │
         ▼
   Tool executes.  Cross-tenant data returned.
```

That missing hop is an authorization decision, and you almost certainly run an engine
that makes them already. It just isn't wired to the point where the agent acts. apparitor
is that wiring: it routes each agent action to a policy decision point (PDP) and maps the
verdict onto the enforcement point's `ALLOW` / `BLOCK` / `HUMAN_IN_THE_LOOP` model.

```text
Agent for alice@acme  →  read_records(tenant="globex")
         │
         ▼
   Safety scanning (PromptGuard, AlignmentCheck, CodeShield, …)            → PASS
         │
         ▼
   apparitor ──────────POST /access/v1/evaluation──────▶  Policy engine (OpenFGA / Cedar / OPA / …)
         │                                                    │
         │  ◀────────────────── { "decision": false } ────────┘
         ▼
   BLOCK: "alice@acme is not authorized to call read_records for tenant globex"
```

## Why not just write the check yourself?

The naive version, `if allowed: run()`, is a security bug in four ways apparitor exists
to handle:

- **The subject is a [confused-deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem)
  trap.** The firewall layer sees model output, not an authenticated principal. Infer *who
  is acting* from the tool call and the agent can name its own privileged subject.
  apparitor takes the subject from the host, request-scoped (at the MCP boundary, from the
  *validated* OAuth token), never from model output. See
  [Identity](#identity-who-the-agent-acts-for).
- **The default failure is fail-open.** A timed-out PDP, a `5xx`, a missing or non-boolean
  `decision`, an unparseable call: each is a falsy `allowed` your `if` waves through.
  apparitor resolves every one to BLOCK or human review; there is no fail-open option. See
  [Fail-closed by default](#fail-closed-by-default).
- **You would write it four times.** The check belongs at the firewall, the MCP server,
  and the agent-to-agent boundary, each with different objects and different identity sources.
  apparitor is one engine behind four adapters.
- **The agent should be more constrained than its user.** A jailbroken agent acting for a
  privileged user must not borrow that user's rights. apparitor can evaluate *both* the
  user's grant and the agent's own permission boundary, proceeding only when both allow.
  This is a separately-audited control that holds across engines. See
  [Level 2](#identity-who-the-agent-acts-for).

And you write no new policy: it stays in the engine your org already authors policy in,
audited where the rest of your authorization lives.

**One engine across enforcement points.** The check runs wherever your stack lets you
intercept the action: inside an agentic firewall (as a
[LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
scanner or a [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) rail), at the
MCP boundary as FastMCP server middleware, or at the agent-to-agent boundary as an A2A
executor. Same engine, same fail-closed semantics everywhere; only the boundary differs.

**One integration, many policy engines.** apparitor speaks the
[AuthZEN 1.0](https://openid.net/specs/authorization-interop-spec-1_0.html) interop
standard, so the same wiring reaches the engines you already author policy in:
**OpenFGA** (Zanzibar / ReBAC, experimental), **Cedar** (policy-as-code), and **OPA /
Rego**, with no policy rewrite. OPA and Cedar also have native backends that skip the
AuthZEN hop.

> **Status: `0.1.1`, beta.** **Shipping today:** the LlamaFirewall, NeMo, FastMCP and A2A
> adapters and the AuthZEN evaluation pipeline, working end-to-end against any AuthZEN 1.0 PDP (OpenFGA,
> Cedar, OPA, Cerbos, Topaz) plus native OPA and in-process Cedar backends, with ≥90% test
> coverage (CI-enforced) on the adapter-free core (see [`CHANGELOG`](CHANGELOG.md)).
> Fail-closed on every error path, subject isolation, and an SSRF-guarded transport are
> tested invariants. An internal adversarial security review (six findings, all fixed) is
> documented in [`docs/security-review.md`](docs/security-review.md), and an independent
> external review is an adoption-gated goal, not yet done. Solo-maintained, best-effort
> cadence. **On the roadmap:** a native OpenFGA backend. See
> [`docs/requirements.md`](docs/requirements.md) for the design and [`ROADMAP`](ROADMAP.md).
> APIs may change.

## Installation

Install from PyPI:

```bash
pip install apparitor
```

Each enforcement point and the in-process Cedar backend are optional extras
(`[llamafirewall]`, `[nemo]`, `[fastmcp]`, `[a2a]`, `[cedar]`). `[llamafirewall]` pulls a
torch / ML stack; the bare install and every other extra do not. See
[docs/setup.md](docs/setup.md#installation) for the full matrix and the per-extra install
commands.

## Quickstart

Pick the enforcement point your stack already has. The same `AuthorizationEngine` runs
behind each one; only the boundary and the identity source differ. Point any of them at an
AuthZEN-compliant policy decision point (PDP) with `pdp_url`, and resolve a subject per
request (recommended) or set a static `agent_id`. See
[Identity: who the agent acts for](#identity-who-the-agent-acts-for).

**FastMCP server middleware** (`pip install "apparitor[fastmcp]"`). Gates `tools/call`,
`resources/read`, and `prompts/get` server-side before the tool runs. The subject is the
*validated* OAuth `sub`, never a host assertion, so register it after your auth middleware.
Worked proxy example in [`examples/gateway/`](examples/gateway/).

```python
from fastmcp import FastMCP
from apparitor.fastmcp import FastMCPAuthorizationMiddleware

server = FastMCP("files", auth=...)  # auth yields the validated token identity
server.add_middleware(FastMCPAuthorizationMiddleware(pdp_url="https://pdp.internal"))
```

**A2A agent executor** (`pip install "apparitor[a2a]"`). Authorizes every agent-to-agent
`agent.invoke` before the wrapped executor runs; the subject is the server's authenticated
peer.

```python
from a2a.server.request_handlers import DefaultRequestHandler
from apparitor.a2a import A2AAuthorizationExecutor

guarded = A2AAuthorizationExecutor(
    MyExecutor(), pdp_url="https://pdp.internal", agent_label="travel-agent"
)
handler = DefaultRequestHandler(agent_executor=guarded, task_store=..., agent_card=...)
```

**LiteLLM Proxy guardrail** (unreleased; `pip install -e ".[litellm]"` from this checkout).
Checks offered tools and returned invocations using the proxy's authenticated key-owner
identity. A dedicated MCP guardrail authorizes server-bound gateway calls before execution.
Configure the corresponding hooks with the [LiteLLM setup guide](docs/litellm.md).

**Inside LlamaFirewall** (`pip install "apparitor[llamafirewall]"`). Bind the scanner to the
assistant role so it gates tool calls before they dispatch. Tool calls in OpenAI, Anthropic,
and LangChain shapes are normalised automatically; an unrecognised shape blocks (fail closed).

```python
from llamafirewall import LlamaFirewall, Role
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(
    config=ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot")
)
firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
result = await firewall.scan_async(assistant_message)  # ALLOW / BLOCK / HUMAN_IN_THE_LOOP
```

**NeMo Guardrails rail** (`pip install "apparitor[nemo]"`). Registers as a custom action; the
rail refuses denied tool calls, fail-closed as a NeMo `RailOutcome`. The rail flow lives in your
NeMo config (see the module docstring). Exercised in [`examples/three-peps/`](examples/three-peps/).

```python
from nemoguardrails import LLMRails, RailsConfig
from apparitor.nemo import NeMoAuthorizationRails

rails = LLMRails(RailsConfig.from_path("config"))
NeMoAuthorizationRails(pdp_url="https://pdp.internal").register(rails)
```

Each adapter has more options (list filtering, dual-principal boundaries, per-hook opt-outs)
documented in its module docstring; see [docs/setup.md](docs/setup.md) for per-engine wiring.
The AuthZEN client and models are **adapter-free** and usable on their own:
`from apparitor.models import EvaluationRequest` needs no firewall dependency.

## Identity: who the agent acts for

Every decision needs a **subject:** the principal your policy is written against. apparitor
never infers it from model or tool output (that would be a [confused
deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem)); the **host** supplies it,
request-scoped. There is a maturity ladder of three levels:

- **Level 0 — static agent identity.** Set `agent_id`; every call is authorized as that
  agent. Enough for policies that don't depend on the end user (*"no agent may call a
  destructive tool"*).
- **Level 1 — the real end user, per request (recommended).** Bind the authenticated user
  for the agent run with `subject_scope(Subject(...))`; it resets on exit, so a subject
  cannot leak to a later request that reuses the same task/event loop.
- **Level 2 — the agentic permission boundary (user ∧ agent).** `DualPrincipalMapper`
  evaluates the user's grant *and* the agent's own boundary, proceeding only when both
  allow, so a jailbroken agent can never borrow its user's rights.

With no resolvable subject the scan fails **closed**. Enforcement points that carry a
*validated* identity of their own populate the same seam: the FastMCP middleware reads the
verified OAuth token's `sub` and it outranks any host-asserted subject. See
[docs/setup.md](docs/setup.md#identity-resolving-the-subject) for the full resolution
order, the three levels with code, and dual-principal wiring.

## Fail-closed by default

Every path that cannot produce a clean ALLOW refuses: an unreachable or timed-out PDP, a
malformed response (a missing or non-boolean `decision` is an error, never a coerced
allow), a missing subject, an unparseable tool call. There is no fail-open option; a PDP
failure resolves per `on_error` to `deny` (default) or `human_review`. PDP URLs must be
HTTPS and pass an SSRF guard, TLS verified and redirects never followed (the only opt-out
is the explicit `allow_insecure_pdp` flag, for local dev). A `review_predicate` can only
*escalate* a decision to `HUMAN_IN_THE_LOOP`, never downgrade one. Decision caching is off
by default and, when enabled, caches ALLOW only, keyed by a digest of the full request
tuple, with a clamped TTL. See [docs/requirements.md](docs/requirements.md) (§3.6–3.9) for
the full failure-handling and caching design.

## Observability

Every decision is timed and counted. The scanner (and the standalone `AuthorizationEngine`)
exposes a `metrics` sink — by default an in-process `InMemoryMetrics` with a latency
histogram and decision/cache counters; pass your own `MetricsSink` to forward to
Prometheus/OpenTelemetry, or `NoopMetrics()` to disable.

```python
m = scanner.metrics
m.latency_histogram()  # [(le_seconds, cumulative_count), …, (+Inf, n)]
m.decisions  # {("allow", "success"): 12, ("block", "error"): 1}
```

Each decision also emits one structured audit line (verdict, status, subject id,
correlation id, resource ids, argument *fingerprint*); raw arguments and tokens are never
logged. The subject id is the decision principal (the OAuth `sub` under FastMCP, which may
be an email), so treat the `apparitor` logger as sensitive. The log format is a stability
contract from `0.1.0`. For a runnable walk-through — configuring the logger, emitting and
parsing every contract line, and a Prometheus scrape — see
[`examples/observability/`](examples/observability/). See [docs/audit-log.md](docs/audit-log.md)
and [docs/requirements.md](docs/requirements.md) (§3.10).

The unreleased Observe additions provide a typed `audit_sink`, trusted tenant/trace/identity
metadata, separate execution outcomes and optional keyed argument fingerprints. A durable
local collector forwards evidence to the reference ingestion service, which offers search,
timelines, operational alerts and a dashboard. Run the [local pipeline demo](docs/observe-pipeline.md)
to exercise restart recovery and delivery after a lost acknowledgement. Hosts supply opaque
identities and policy provenance; evidence supports investigation and compliance work but
does not establish legal compliance.

## What apparitor connects

**Enforcement points** (the agent-side hooks apparitor plugs into):

| Enforcement point | Vendor | Status |
| --- | --- | --- |
| [**LlamaFirewall**](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | Meta | shipping (`AuthZENScanner`) |
| [**NeMo Guardrails**](https://github.com/NVIDIA/NeMo-Guardrails) | NVIDIA | shipping (`NeMoAuthorizationRails`) |
| [**FastMCP**](https://github.com/PrefectHQ/fastmcp) server middleware | Prefect | shipping (`FastMCPAuthorizationMiddleware`) |
| [**A2A**](https://a2a-protocol.org/) agent executor | Linux Foundation | shipping (`A2AAuthorizationExecutor`) |
| [**LiteLLM Proxy**](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail) | BerriAI | unreleased (`LiteLLMAuthorizationGuardrail`); [setup and boundaries](docs/litellm.md) |

**Policy engines** (where the authorization decision is made). apparitor reaches these over
AuthZEN; OPA and Cedar also have native backends that skip the AuthZEN hop, selected by
config (`backend="opa"` / `backend="cedar"`):

| Engine | Paradigm | How apparitor reaches it | Example |
| --- | --- | --- | --- |
| **Mock PDP** (testing/demo) | n/a | AuthZEN | [`examples/mock_pdp/`](examples/mock_pdp/) |
| **OpenFGA** | Zanzibar / ReBAC | native AuthZEN (experimental) | [`examples/openfga/`](examples/openfga/) |
| **Cedar** | policy-as-code (ABAC) | AuthZEN gateway · native in-process (`backend="cedar"`) | [`examples/cedar/`](examples/cedar/) |
| **OPA / Rego** | policy-as-code | AuthZEN gateway · native Data API (`backend="opa"`) | [`examples/opa/`](examples/opa/) |
| **Amazon Verified Permissions** | managed Cedar | [AWS AuthZEN interface](https://github.com/aws-samples/sample-authzen-interface-verified-permissions) | [`examples/avp/`](examples/avp/) |
| Any AuthZEN 1.0 PDP (Cerbos, Topaz, …) | varies | AuthZEN | [`docs/setup.md`](docs/setup.md) |

## Documentation

- [Technical requirements & design decisions](docs/requirements.md)
- [Architecture](docs/architecture.md)
- [Setup: connecting to a policy engine](docs/setup.md)
- [EU AI Act authorization evidence reference](docs/eu-ai-act.md)
- [Structured compliance evidence and state-law status](docs/compliance-evidence.md)
- [LiteLLM Proxy setup](docs/litellm.md)
- [Conventional API authorization](docs/api.md)
- [Observe events and trusted metadata](docs/observe-events.md)
- [Durable local collector](docs/collector.md)
- [Observe reference service and dashboard](docs/observe.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Releasing](RELEASING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[Apache License 2.0](LICENSE).
