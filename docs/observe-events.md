# Observe event metadata

Audit records can carry optional execution linkage supplied by the host: trace, run, span,
parent-span and call identifiers; opaque session, device, user, agent and workload references;
integration, action and resource references; a bounded reason code; and an explicit coverage
status of `instrumented` or `unknown`. A parent span requires a span. These values describe
host assertions and provenance; they do not prove execution, identity, authorization or legal
compliance.

Hosts must provide tenant-scoped opaque references. Raw provider, account, device, user,
session, resource and workload identifiers do not belong in audit records. The library checks
types and bounds but cannot determine whether a supplied reference is actually opaque.

An audit sink does not create identity or provenance automatically. Hosts must establish
`audit_metadata_scope` at the authenticated request boundary before an adapter is called.
The LiteLLM adapter additionally accepts a trusted metadata resolver for its proxy hooks;
its setup guide demonstrates that binding. Without a trusted scope, the engine emits no
typed evidence and increments `audit_failures`. `audit_metadata_scope(None)` explicitly
clears an inherited scope and restores it on exit.

`argument_fingerprint` creates a tenant-bound HMAC-SHA-256 value from the normalized tool name
and exact JSON arguments. It requires a host-managed key of at least 32 bytes, rejects
unsupported or oversized input, and retains no raw argument content. Hosts should rotate and
scope keys according to their retention policy. No unkeyed digest is provided because stable
argument values can become an identity or content oracle.

Pass `audit_sink` and `audit_fingerprint_key` to the engine or an adapter constructor to
fingerprint normalized invocation arguments before the policy mapper redacts values. The
engine uses the trusted audit scope's tenant, records its integration label and derives a
reason code from the decision. Oversized or unsupported arguments leave fingerprints empty
and increment `audit_fingerprint_failures`; they do not change the authorization result.
Per-item checks carry the fingerprint of their own normalized call. For a tool listing,
that describes its empty declaration arguments; it does not identify a later invocation.

`collection_gap` records a positive bounded count and reason supplied by the host when expected
observations were unavailable. It is a gap assertion, not evidence about the missing events.
`boundary_refusal` records a deliberate pre-evaluation refusal (for example an unsupported
execution route); it is counted separately from `mapping_failure` and policy decisions.
`AuditEvidence.from_dict` accepts only the known schema fields, converts JSON reference arrays
to immutable tuples and applies the same timestamp, enum, bound and fixed `not_collected`
validation as locally constructed records.
