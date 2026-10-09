# LiteLLM Proxy

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
audit scope, and does not change the authorization verdict; the engine counts the missing
evidence in `audit_failures`. Pass `audit_fingerprint_key` to emit tenant-bound HMAC fingerprints
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

LiteLLM's A2A `send_message` routes are refused in pre-call, before an agent can run.
Their post-call results cannot authorize actions an agent already performed. Use Apparitor's
A2A executor at the agent server and scope this proxy guardrail to supported model routes.
Background Responses API requests are likewise refused before dispatch because their completed
output would escape the synchronous post-call authorization boundary.

Pre-call declarations support client-executed function tools, including Anthropic's ordinary
named tool declarations. Provider-hosted, custom, computer, MCP and other tool kinds are
refused before the provider call. Unknown Anthropic content blocks are also refused; only
ordinary text/thinking blocks and supported `tool_use` calls pass post-call classification.
Non-null `mcp_servers` and `web_search_options` request fields are refused independently
of the `tools` array, including empty configurations. Hosts must restrict routes and provider
configuration to client-executed tools; the hooks cannot discover execution capabilities
enabled only in provider or proxy configuration.
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

## Upstream and release work

Before release, run the LiteLLM optional-dependency test job against the declared minimum and
latest supported versions, then build the wheel and confirm importing core `apparitor` still
works without LiteLLM installed. A LiteLLM upstream submission would add Apparitor to its
custom guardrail registry and documentation; keep that separate from publishing the Apparitor
extra, and validate the proxy configuration against the exact LiteLLM release selected for the
submission.
