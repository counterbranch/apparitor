# Framework-neutral authorization API

Apparitor is an in-process authorization library. The stable seam for a conventional
custom-authz endpoint is `AuthorizationEngine.evaluate_requests()`: the host resolves an
authenticated principal, constructs an `EvaluationRequest`, and treats only
`Verdict.ALLOW` with `VerdictStatus.SUCCESS` as permission to continue.

`examples/api/` contains a runnable FastAPI boundary and ASGI tests. Install its optional
example dependencies with `pip install -r examples/api/requirements.txt`; the package's
core dependency set does not include FastAPI. The sample's `x-demo-subject` and
`x-demo-tenant` headers are an explicit fixture. Replace `demo_principal` with the host's
verified authentication dependency. Do not decode an unverified bearer token in this
adapter. The tenant is taken from that trusted resolver and compared with the request body
before evaluation; it is also forwarded in AuthZEN `context` for policy cross-checking.
Caller-supplied properties are explicitly untrusted request data under
`context.requested_properties`. They never populate authoritative resource attributes.
The host must obtain ownership, classification and other authority-bearing attributes
from its own resource store before adding them to a policy request.

The example reuses one long-lived engine and its pooled client for the app lifetime. It
returns HTTP 200 only for `allow/success`, HTTP 403 for a clean deny or review, HTTP 401 for
missing identity, and HTTP 503 for a PDP or evaluation error. The `/authorize` route is
decision-only: it does not execute an operation or observe an execution result. The
protected `/documents/{id}?tenant=...` route shows the separate pattern: only after an allow does it
read from the fixed synthetic store, and it records `succeeded` or `not_started` through
the host-provided audit sink. Request and output fingerprints are short keyed HMAC-SHA-256 values;
raw properties, prompts, credentials, and token material are not logged or returned.
Fingerprints identify a request for correlation, not proof of execution.
The configured audit key must contain at least 32 bytes. Without an audit sink/key,
the app generates a private fingerprint key for its lifetime.

This boundary complements Counterbranch's regression evidence: Counterbranch records
baseline/candidate policy observations, while an Apparitor runtime call records a
point-in-time principal, tuple, and decision; the protected route can additionally record
the host-observed execution outcome. Apparitor does not need a remote authorization service
for this use case. Retention, tamper evidence, aggregation, and telemetry export remain
deployment responsibilities.

Pass the same host-owned `AuditSink` into `AuthorizationEngine(audit_sink=...)`. The sample
reads that sink through the engine, scopes opaque tenant/principal/request references with
`audit_metadata_scope`, and correlates the execution outcome to the preceding decision's
`event_id`. If the execution sink fails, the route logs only a generic warning and preserves
the authorization result.

Run the local fixture on loopback only with `python examples/api/app.py`. It binds to
`127.0.0.1`; its demo resolver uses headers as an explicit fixture and must not be used as
production authentication. Install the optional example dependencies first with
`pip install -r examples/api/requirements.txt`.
