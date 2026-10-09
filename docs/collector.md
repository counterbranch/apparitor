# Local Observe collector

`LocalAuditCollector` is an opt-in, host-managed SQLite outbox for `AuditEvidence`.
`record()` commits evidence before returning. Delivery starts only when the host calls
`flush()` with its own async transport; the collector creates no background task and
does not reuse PDP authentication, credentials, or billing configuration.

```python
from apparitor.collector import DeliveryResult, LocalAuditCollector

collector = LocalAuditCollector("/var/lib/example/apparitor-audit.sqlite3")
collector.record(evidence)


async def send(batch):
    # Bind this to a receiver owned and authenticated by the host. Send each
    # event.payload unchanged and use event.evidence_id as its idempotency key.
    accepted_ids = await receiver.store(batch)
    return DeliveryResult(frozenset(accepted_ids))


result = await collector.flush(send)
collector.close()
```

The database parent must already exist and be owned by the current operating-system user.
The collector rejects symlink database paths and sets the database mode to `0600`. SQLite
uses WAL mode and `synchronous=FULL`. A separate collector instance can reopen the queue
after a process restart.

Configure `max_event_bytes`, `max_pending_events`, and `max_pending_bytes` for the host's
retention budget. These are transactional payload and row limits, not a strict filesystem
quota: SQLite database and WAL housekeeping can consume additional space. A full queue or
oversized event is refused and counted; existing evidence is never evicted silently.

Evidence IDs are the delivery idempotency keys. Re-recording the same ID and identical
canonical payload succeeds without adding a row. Reusing an ID with different content is
rejected and counted as a conflict. The collector retains a bounded set of recent delivery
receipts for this local check and prunes the oldest receipts as housekeeping; receivers must
apply the same idempotency rule because delivery is at least once and a lost response,
expired worker lease, or ID older than the local receipt window can be sent again.

The transport returns only IDs it has durably accepted. Missing acknowledgements remain
queued. Partial acknowledgements remove only accepted rows. Exceptions and unacknowledged
rows increment retry counters and use bounded exponential backoff with jitter within the
caller's retry budget. Cancelling `flush()` releases its leases before propagating
cancellation. Database leases prevent two local workers from intentionally sending the
same live batch concurrently; an expired lease permits recovery after a crashed process.
If lease cleanup itself fails during cancellation, the original cancellation still
propagates, a generic warning reports cleanup failure, and pending rows recover after
lease expiry when storage is available again.

`status()` reports pending rows and bytes, cumulative deliveries, retries, failures,
refusals and conflicts, plus the oldest pending age. It contains no evidence payloads or
identifiers. These counters expose collection gaps but do not attest delivery completeness
or legal compliance.

The host owns the receiver binding. Validate a fixed HTTPS destination, verify TLS, block
redirects and private or local address resolution unless explicitly intended, keep Observe
credentials separate from PDP credentials, and return acknowledgements only after durable
receiver storage. The collector intentionally provides no default HTTP exporter because a
generic URL option cannot establish those deployment-specific trust boundaries.
