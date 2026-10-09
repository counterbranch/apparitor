# Setup: connecting to a policy engine

apparitor speaks the AuthZEN 1.0 Access Evaluation API, so it reaches any compliant policy
decision point (PDP). Point it at an endpoint:

```python
from apparitor import AuthZENScanner

scanner = AuthZENScanner(pdp_url="https://pdp.internal")
```

By default it `POST`s to `/access/v1/evaluation` (single) and `/access/v1/evaluations`
(batch). Override the paths via `ScannerConfig` if your PDP mounts them elsewhere or sits
behind a gateway.

## Installation

Install from PyPI, adding the extra(s) your enforcement point and backend need:

```bash
pip install apparitor                    # AuthZEN client + models, no firewall dependency
pip install "apparitor[llamafirewall]"   # LlamaFirewall scanner (pulls torch / ML stack)
pip install "apparitor[nemo]"            # NeMo Guardrails rail
pip install "apparitor[fastmcp]"         # FastMCP server middleware
pip install "apparitor[a2a]"             # A2A agent-executor adapter
pip install "apparitor[cedar]"           # in-process Cedar backend (cedarpy, no server)
```

`[llamafirewall]` pulls LlamaFirewall's ML dependencies (torch, PromptGuard); the bare
install and all other extras work without it.

The LiteLLM Proxy guardrail is unreleased. Install its `[litellm]` extra from this
checkout until a release includes it:

```bash
pip install -e ".[litellm]"
```

Running the HTTP proxy also requires LiteLLM's own `proxy` extra. See
[litellm.md](litellm.md) for both required hooks, trusted identity and supported tool boundaries.

## Authentication & TLS (bring-your-own httpx client)

For bearer tokens, mTLS, custom CA roots, or proxies, pass a pre-configured
`httpx.AsyncClient`. Secrets stay in your client and never touch message content or logs.

```python
import httpx
from apparitor import AuthZENScanner, ScannerConfig

http = httpx.AsyncClient(
    headers={"Authorization": f"Bearer {token}"},
    verify="/etc/ssl/corp-ca.pem",
)
scanner = AuthZENScanner(
    config=ScannerConfig(pdp_url="https://pdp.internal"),
    http_client=http,
)
```

> **Security:** `pdp_url` must be HTTPS and must not resolve to a private/link-local
> address unless `allow_insecure_pdp=True` (local development only). TLS verification is on
> by default. See [requirements.md §3.7](requirements.md).

## Identity: resolving the subject

The **subject** is the principal the PDP authorizes, usually the end user the agent acts
for, not the agent process. apparitor resolves it per request, in this order, and fails
closed (`AuthZENConfigError`) if none is found:

1. a `subject` in `current_request_context`,
2. the `current_subject` context variable (set it with `subject_scope`),
3. `config.agent_id`, a static fallback, mapped to `Subject(type=config.subject_type, id=agent_id)`.

Bind the authenticated user for the agent run with `subject_scope` rather than setting
`current_subject` directly. It resets the value on exit, so a subject can never leak to a
later request that reuses the same task or event loop:

```python
from apparitor import Subject, subject_scope

# In your request handler, where the user is already authenticated:
with subject_scope(Subject(type="user", id=authenticated_user_id)):
    result = await firewall.scan_async(assistant_message)
```

Attach request-scoped enrichment via `current_request_context`: `user_id`, `conversation_id`,
and `correlation_id` are forwarded to the PDP as AuthZEN `context` for policy conditions. (A
`subject` placed here is instead used to resolve the request's subject, per the order above,
not forwarded as context.) The `correlation_id` value also appears verbatim in the C1 audit
log line. See [audit-log.md](audit-log.md) for the full log schema and stability
contract.

Use `request_context_scope` rather than calling `.set()/.reset()` directly. It ensures the
context is always cleared on exit and cannot leak to a later request that reuses the same task:

```python
from apparitor import request_context_scope

with request_context_scope({"user_id": "alice@acme.com", "conversation_id": "c-42"}):
    result = await firewall.scan_async(assistant_message)
```

> **Security:** the subject and request context must be **host-trusted, out-of-band** data,
> established by your authentication layer, never derived from model output or a tool result.
> Deriving the principal from model output would let a prompt-injected agent choose its own
> identity (a confused deputy). See [requirements.md](requirements.md).

### Maturity levels and permission boundaries (user ∧ agent)

The resolution order above is a maturity ladder. **Level 0** is the static `agent_id`
fallback — every call authorized as that agent, enough for policies that don't depend on
the end user (*"no agent may call a destructive tool"*). **Level 1** (recommended) is the
request-scoped end user via `subject_scope`. **Level 2** adds the agent's *own* permission
boundary on top of the user's grant, for when the agent must be more constrained than the
human it acts for.

`DualPrincipalMapper` evaluates **two** decisions per call — the end user's grant *and* the
agent's boundary — as one batched, all-allow-or-block round trip, so a jailbroken agent can
never exercise a permission its boundary denies even when the user holds it:

```python
from apparitor import AuthZENScanner, DualPrincipalMapper, ScannerConfig

config = ScannerConfig(pdp_url="https://pdp.internal", agent_id="travel-bot")
scanner = AuthZENScanner(config=config, mapper=DualPrincipalMapper(config))
# per request: subject_scope(user) supplies the user leg; "travel-bot" is the boundary
```

Unlike an in-policy `forbid` (which works when one PDP holds all your policy), the dual
mapper makes the boundary a **separate, separately-audited decision** that holds across
engines and policy stores. The `mapper=` seam reaches the scanner, the NeMo rail, and the
FastMCP `tools/call` and listing paths. The A2A executor and the FastMCP `resources/read` /
`prompts/get` paths take a `boundary_subject` constructor argument instead; a full FastMCP
deployment sets both. Either principal unresolvable fails closed, and dual calls always
batch, so the opt-in ALLOW cache is not consulted.

## Mock PDP

A tiny in-process AuthZEN PDP for tests and demos (configurable allow/deny rules, no
external services) lives in [`examples/mock_pdp/`](../examples/mock_pdp/). Start here.

## OpenFGA (Zanzibar / relationship-based)

[OpenFGA](https://openfga.dev) exposes the AuthZEN Access Evaluation API **natively**
(single and batch) as an [experimental feature](https://openfga.dev/docs/interacting/authzen).
Enable it with the AuthZEN experimental flag and pin the server version, since the API
surface may still change. Agent tool authorization maps cleanly onto OpenFGA's
`type:id` + relation model: `resource{type:"tool", id:<name>}` and an
`action`/relation like `tool_call.execute`. The worked example lives in
[`examples/openfga/`](../examples/openfga/).

## Cedar (policy-as-code)

[Cedar](https://www.cedarpolicy.com/) is reachable over AuthZEN via a gateway shim that
translates AuthZEN requests into Cedar `is_authorized` calls. The
[`examples/cedar/`](../examples/cedar/) example runs Cedar locally behind such a gateway
with sample policies.

### Cedar native backend (`backend="cedar"`, `[cedar]` extra)

The native backend evaluates Cedar policies **in-process** via `cedarpy`: no server, no
gateway, no network. The decision never leaves the host, making this the sovereignty- and
ops-lightest Cedar option.

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(
    config=ScannerConfig(
        backend="cedar",
        cedar_policies_path="policies/authz.cedar",
        cedar_entities_path="policies/entities.json",
    )
)
```

`cedar_policies_path` and `cedar_entities_path` are required; `cedar_schema_path` is
optional (enables schema validation at startup). Policies and entities are loaded once at
construction. See [`examples/cedar/`](../examples/cedar/) for a full worked example.

## OPA / Rego (policy-as-code)

OPA is reachable over AuthZEN via a gateway, or by running an OPA build that serves the
AuthZEN endpoints natively (e.g.
[`kanywst/opa-authzen-plugin`](https://github.com/kanywst/opa-authzen-plugin)). The
[`examples/opa/`](../examples/opa/) example runs OPA locally behind such a gateway with
sample Rego policies.

### OPA native backend (`backend="opa"`)

The native backend talks OPA's Data API (`POST /v1/data/<path>`) directly, with no AuthZEN
gateway required. The same hardened transport (SSRF guard, TLS, bounded retries) used by
the AuthZEN backend applies here.

```python
from apparitor import AuthZENScanner, ScannerConfig

scanner = AuthZENScanner(
    config=ScannerConfig(
        backend="opa",
        pdp_url="https://opa.internal:8181",
        opa_decision_path="myorg/authz/allow",
    )
)
```

For a local OPA instance (`http://localhost:8181`) set `allow_insecure_pdp=True` (local development only).

`opa_decision_path` must match your Rego package and boolean rule (e.g. package
`myorg.authz`, rule `allow` → path `myorg/authz/allow`). The default matches the example
policy in this repo. A non-matching path fails closed. See [`examples/opa/`](../examples/opa/)
for a full worked example.

## Amazon Verified Permissions (managed Cedar)

AVP is the managed AWS Cedar service. AWS publishes an
[open-source AuthZEN interface for AVP](https://github.com/aws-samples/sample-authzen-interface-verified-permissions)
(a Lambda translating AuthZEN ↔ AVP `IsAuthorized`). Because it needs an AWS account, it
is a later **cloud** example ([`examples/avp/`](../examples/avp/)), not part of the
local/CI set.

## Other PDPs

OPA (via [`kanywst/opa-authzen-plugin`](https://github.com/kanywst/opa-authzen-plugin)),
Cerbos, and Topaz also expose AuthZEN endpoints; any AuthZEN 1.0 PDP works. Resource and
subject **type vocabularies differ** between PDPs (OpenFGA's `type:id` relations vs Cedar
entities/actions vs OPA's free-form input). Adapt the `ToolCallMapper` to your PDP's
schema.
