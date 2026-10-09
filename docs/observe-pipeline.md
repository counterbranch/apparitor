# Local Observe pipeline

The local demo connects the real `AuthorizationEngine` evidence path to
`LocalAuditCollector`, then delivers through an in-process `httpx.ASGITransport` to the
Observe reference app. It makes genuine allow and block decisions with a deterministic
synthetic backend and records explicit succeeded and not-started execution outcomes.

```bash
python -m examples.observe.demo
```

The demo creates a temporary outbox and Observe database, generates separate random writer
and reader credentials in memory, and removes the directory on exit. It opens no network
socket and prints only operational counts. Trusted metadata uses opaque tenant, trace, user,
agent, request and resource references plus an explicit policy version; raw principals,
arguments, credentials and event payloads are not printed.

Delivery is deliberately at least once. The demo can simulate a response being lost after
the server durably ingests a batch. The collector retains the records, retries them, and the
server's `(tenant_ref, evidence_id)` idempotency key prevents duplicate summary, timeline or
alert counts. The transport accepts at most 100 records and treats the response as an
acknowledgement only when its ID set exactly matches the sent batch.

The outbox is closed and reopened before delivery to exercise process-restart persistence.
The resulting reader queries cover `/v1/summary`, `/v1/traces/{trace_id}`, and `/v1/alerts`.
This is a local integration example, not a hosted service configuration or performance
benchmark.
