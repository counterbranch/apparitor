# LiteLLM Proxy

Use this adapter with an installed LiteLLM Proxy. Its host needs LiteLLM's `proxy` extra;
Apparitor's `litellm` extra keeps the library dependency separate. To run the proxy integration
tests, install `pip install -e '.[dev,litellm]' 'litellm[proxy]'` and the HTTP example
requirements. CI imports the proxy dispatcher before testing so missing proxy dependencies
fail that job rather than silently skipping its dispatcher regression.

`apparitor.litellm.LiteLLMAuthorizationGuardrail` is a LiteLLM Proxy custom guardrail. It
uses the proxy's authenticated `UserAPIKeyAuth.user_id` as an Apparitor `user` subject,
checks tools before they are offered to the model, and checks every tool call in the completed
model response before the response reaches the client.

This integration is unreleased. Install the optional extra from this checkout and create
a small guardrail module:

```bash
pip install -e '.[litellm]'
```

Install LiteLLM's own `proxy` extra to run its HTTP proxy. Apparitor's extra supplies
the guardrail SDK dependency; it does not install or configure a proxy server.

```python
import os

from apparitor.litellm import LiteLLMAuthorizationGuardrail


class ApparitorGuardrail(LiteLLMAuthorizationGuardrail):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(pdp_url=os.environ["APPARITOR_PDP_URL"], **kwargs)
```

Load that instance in the proxy configuration:

```yaml
guardrails:
  - guardrail_name: apparitor
    litellm_params:
      guardrail: path.to.callback.ApparitorGuardrail
      mode:
        - pre_call
        - post_call
      default_on: true
```

The exact module path is relative to the proxy process's import path. Run the callback on
both `pre_call` and `post_call`; pre-call checks alone govern which tools the model sees but
cannot authorize model-selected arguments.
The constructor rejects configurations that disable either required hook.

## Identity and policy shape

The default resolver maps the authenticated LiteLLM key owner to:

```json
{"type": "user", "id": "<UserAPIKeyAuth.user_id>"}
```

A missing identity blocks tool-bearing traffic. Request `metadata`, messages, tool arguments,
the OpenAI `user` field, and model output cannot set or override the subject. A deployment
whose trusted authentication object uses another principal can pass an `identity_resolver`
that accepts `UserAPIKeyAuth` and returns an Apparitor `Subject`; returning `None` refuses.

When `audit_sink` is configured, `audit_metadata_resolver` is required. It receives only the
authenticated `UserAPIKeyAuth` object and must return a validated `AuditMetadata` for that
request. Apparitor scopes that metadata across the whole pre-call, post-call, or streaming hook,
including early refusals, then clears it. Request fields and model output never reach the
resolver. A resolver failure is logged without its exception detail, clears any unrelated outer
audit scope, and does not change the authorization verdict. Monitor the guardrail's public
`audit_metadata_failures` counter, which increments immediately even on hooks with no tool
calls, and `audit_failures`, which counts failed engine evidence emissions. These counters
are process-local; the host must export and alert on them separately from the evidence sink.
The sink alone cannot show this loss: without trusted metadata Apparitor cannot safely assign
a tenant to a `collection_gap` record. The host may emit such a record through a separately
trusted audit scope. Do not interpret silence at the sink as complete collection.
Pass `audit_fingerprint_key` to emit tenant-bound HMAC fingerprints
of exact tool arguments without retaining the arguments themselves. Other Apparitor adapters
that do not have an authentication-object resolver require the host to establish an explicit
`audit_metadata_scope` around each request.

Pre-call declarations are evaluated as tool calls with empty arguments. Post-call evaluation
uses each exact name and argument object returned by the model. Policy should therefore treat
pre-call authorization as permission to expose a tool and post-call authorization as
permission to execute the selected invocation. Denying either blocks the request or response.
`authorize_offered_tools=False` skips only the declaration policy check. Tool-shape validation
and unsupported provider-tool refusal remain mandatory, as does post-call authorization.

Post-call enforcement supports OpenAI chat `tool_calls` and legacy `function_call`, OpenAI
Responses API `function_call` output items, and Anthropic Messages `tool_use` blocks. LiteLLM's
typed embedding, image, text-completion, transcription, rerank, file, batch, and fine-tuning
responses pass without a policy call because they contain no executable output. Unknown response
families and malformed executable shapes fail closed.
Responses API custom, computer, MCP, shell, code-interpreter, image-generation, web-search,
apply-patch, programmatic, and tool-search calls are not mapped to Apparitor tool resources and
are refused. Add a server-side adapter at the corresponding execution boundary before enabling
those call types.
Tool-result, MCP discovery/approval, and tool-search output items are also refused, even when
the response contains no call item. A post-call hook cannot authorize work already performed
by a provider; refusing its output prevents releasing the unverified result but cannot undo
that work. Only ordinary message, reasoning and compaction items pass without a tool check.

LiteLLM's A2A `send_message` routes are refused in pre-call, before an agent can run.
Their post-call results cannot authorize actions an agent already performed. Use Apparitor's
A2A executor at the agent server and scope this proxy guardrail to supported model routes.
Background Responses API requests are likewise refused before dispatch because their completed
output would escape the synchronous post-call authorization boundary.
Realtime, Responses WebSocket and generic passthrough routes are also refused:
these routes cannot supply the completed, client-executed function-call
boundary required by this adapter.
For the standalone MCP gateway, also install the dedicated MCP guardrail below. The model
guardrail's `pre_call`/`post_call` hooks do not mediate gateway execution.

Pre-call declarations support client-executed function tools, including Anthropic's ordinary
named tool declarations. Provider-hosted, custom, computer, MCP and other tool kinds are
refused before the provider call. Unknown Anthropic content blocks are also refused; only
ordinary text/thinking blocks and supported `tool_use` calls pass post-call classification.
Non-null `mcp_servers` and `web_search_options` request fields are refused independently
of the `tools` array, including empty configurations. Hosts must restrict routes and provider
configuration to client-executed tools. Non-null `tools`, `functions`, `mcp_servers` or
`web_search_options` in `extra_body` are refused because provider passthrough fields can
override the top-level request after pre-call validation. At either request level,
`background` and `stream` must be absent, null or false. Other provider parameters in an
`extra_body` mapping remain supported. The hooks cannot discover execution capabilities
enabled only in provider or proxy configuration.
Disable proxy-side automatic tool execution and injected tools on these routes. The client
executor must wait for successful post-call authorization before executing any returned call.
Other LiteLLM telemetry configuration remains the host's responsibility.

The authorization hooks do not use LiteLLM's generic raw-response logging decorator. They
preserve the response for its intended caller without copying content or tool arguments into
guardrail logging metadata. Use Apparitor's bounded evidence sink for authorization telemetry.

## Streaming boundary

Streaming requests are refused in `pre_call`, before LiteLLM contacts the provider. Tool-call
names and arguments arrive across multiple deltas, so releasing any chunk before the complete
call is authorized creates a bypass. Buffering arbitrary provider output would instead expose
the proxy to unbounded memory use. The iterator hook also refuses without consuming or releasing
a chunk as a defense if a stream reaches it through another path. Use a non-streaming chat
completion for tool-capable routes. Apply a separate content-only guardrail to streaming routes
that cannot produce executable calls.

The guardrail covers LiteLLM Proxy lifecycle hooks. Direct `litellm.completion()` SDK calls do
not receive proxy `UserAPIKeyAuth` and are outside this integration. It authorizes model-returned
calls before a client can execute them; it cannot enforce a client that ignores the blocked
proxy response or executes tools through a separate channel. Put a server-side adapter such as
Apparitor's FastMCP middleware at the execution boundary when that boundary is available.

Call `await guardrail.aclose()` during proxy shutdown when Apparitor owns the PDP client.

## MCP gateway execution

`LiteLLMMCPAuthorizationGuardrail` uses LiteLLM's `pre_mcp_call` event to authorize each
resolved gateway tool invocation before the upstream call starts. Install it alongside
the model guardrail when serving both surfaces:

```python
from apparitor.litellm import LiteLLMMCPAuthorizationGuardrail


class ApparitorMCPGuardrail(LiteLLMMCPAuthorizationGuardrail):
    def __init__(self, **kwargs: object) -> None:
        super().__init__(pdp_url=os.environ["APPARITOR_PDP_URL"], **kwargs)
```

```yaml
  - guardrail_name: apparitor-mcp
    litellm_params:
      guardrail: path.to.callback.ApparitorMCPGuardrail
      mode:
        - pre_mcp_call
      default_on: true
```

`default_on: true` is required. LiteLLM's configuration loader passes false when this
setting is omitted, and Apparitor rejects that configuration at startup. Direct construction
defaults to true.

The complete two-guardrail configuration is in `examples/litellm/config.yaml`. Keep MCP
authorization last among sequential pre-MCP guardrails, after every trusted argument
rewriter. It evaluates the effective `modified_arguments` when LiteLLM will apply them,
otherwise the original `mcp_arguments`, and returns the payload unchanged. Rewriters must
use LiteLLM's `modified_arguments` contract; replacing or mutating `mcp_arguments` itself
can change the authorization input without changing execution. The constructor rejects parallel
evaluation and `scan_raw_request`, which could authorize arguments different
from the invocation. Do not permit subsequent hooks to rewrite arguments or routing, disable
this guardrail through key/team metadata, or skip guardrails on these keys' execution paths.

Identity comes from the authenticated `UserAPIKeyAuth`, with the same resolver and audit
configuration as the model guardrail. The default mapper produces
`{"type": "mcp_tool", "id": "<server-label>/<normalized-tool-name>"}`. LiteLLM supplies
the resolved server's alias, server name or name as the label; this SDK hook does not expose
its stable `server_id`. Keep labels unique and stable for the lifetime of their policies,
and update policies deliberately when labels change. Missing labels and labels/tool names
containing `/` fail closed. A custom mapper must preserve the server boundary, available in
`request_context["mcp_server_label"]`. Arguments retain Apparitor's existing forwarding and
redaction settings; use `redact_arguments=False` if a policy must inspect values, and treat
those values as untrusted tool input.

Every invocation of this guardrail requires resolved `mcp_tool_name`, `mcp_arguments` and
`mcp_server_name`. Preliminary REST or virtual-tool payloads without that context are refused,
even for authenticated callers. This prevents an unresolved call from proceeding in expectation
of a later authorization hook. Raw REST routing fields (`name`, `arguments`, `server_id`)
also cause refusal, including when callers supply forged `mcp_*` fields alongside them.
LiteLLM's virtual `mcp_tool_call` and `/mcp/proxy` `call_tool` wrappers
are therefore unsupported when they dispatch unresolved payloads through `pre_mcp_call`.

This contract is qualified against LiteLLM 1.104.2's MCP manager and virtual-tool pipeline,
using a synthetic outbound executor and PDP. Keep the proxy logger and callback registration
present on all gateway execution paths. A direct manager call without a proxy logger does not
invoke this adapter and is outside its enforcement boundary; deploy upstream FastMCP middleware
if callers can reach that path. No callback can intercept an executor that never invokes it.

Each invocation is authorized separately; there is no atomic batch authorization. Deny,
human-review and PDP-error outcomes stop execution. Authorization evidence does not prove
execution succeeded; hosts must record execution outcomes separately. `during_mcp_call`
runs concurrently with execution and is deliberately excluded from this adapter.

Gateway discovery, tool search, resource reads and prompt retrieval are outside this
execution hook. Use LiteLLM's server/key access controls for discovery and disable uncovered
surfaces, or put Apparitor's FastMCP middleware on the upstream server for those boundaries.
This hook also does not cover provider-hosted MCP calls, direct SDK calls or A2A/skill tools;
keep their separate enforcement and route restrictions.

## Upstream and release work

Before release, run the LiteLLM optional-dependency test job against the declared minimum and
latest supported versions, then build the wheel and confirm importing core `apparitor` still
works without LiteLLM installed. A LiteLLM upstream submission would add Apparitor to its
custom guardrail registry and documentation; keep that separate from publishing the Apparitor
extra, and validate the proxy configuration against the exact LiteLLM release selected for the
submission.
