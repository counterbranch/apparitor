# Observe local reference

`examples/observe` is a small local control-plane reference for receiving Apparitor
`AuditEvidence`, retaining it in SQLite, and investigating authorization activity. It keeps
policy decisions in the existing local PDP path; observation does not authorize a tool call
and does not replace the JSONL or host-managed audit sinks.

The service provides separate writer and reader credentials scoped to an opaque tenant
reference. The server selects the tenant from the credential, rejects mismatches in payloads
and queries, and never trusts a body field to choose a tenant. Ingestion is transactional.
Repeating an identical `evidence_id` is idempotent; reusing it with different content is a
conflict. An acknowledgement lists only IDs committed durably by SQLite.

Generate independent random credentials and start the service on loopback:

```bash
python - <<'PY'
import json, secrets
print(json.dumps({
    secrets.token_urlsafe(32): {"tenant_ref": "demo-tenant", "role": "writer"},
    secrets.token_urlsafe(32): {"tenant_ref": "demo-tenant", "role": "reader"},
}))
PY
export APPARITOR_OBSERVE_CREDENTIALS='<paste the generated JSON>'
python -m pip install -r examples/observe/requirements.txt
python examples/observe/app.py
```

Send a bounded batch to `POST /v1/events:ingest` with its writer bearer credential. Readers
can use `GET /v1/events` with actor, action, resource, policy, outcome, time, and bounded
pagination filters. `GET /v1/traces/{trace_id}` orders a trace by observation time and uses
the same bounded pagination model;
`GET /v1/summary`, `GET /v1/alerts`, and `GET /v1/events/{evidence_id}` support investigation.
The browser page at `http://127.0.0.1:8765/` keeps a manually entered reader token only in
JavaScript memory and renders server data as text.

Events use opaque references and the strict, bounded evidence schema. Raw prompts,
responses, credentials, request arguments, and protected attributes do not belong in this
store. Alerts identify operational policy blocks, evaluation faults, and collection gaps;
they are not a statutory incident determination. Summary provenance states that counts come
from stored events rather than an independently attested source. Summary and alert views
inspect at most the most recent 1,000 tenant events and return the tenant total, rows
inspected, and a `truncated` flag. Treat truncated results as a recent window rather than
whole-history metrics.

This example serializes its bounded SQLite operations on one application thread. It is a
single-process reference rather than a production-throughput architecture. It does not
provide a managed production UI,
endpoint detection and response, automatic asset discovery, cryptographic evidence
attestation, key rotation, retention administration, high availability, or a compliance
certification. Put a production-grade authenticated gateway, encryption, backup, retention,
and access-review controls around any deployment derived from it.
