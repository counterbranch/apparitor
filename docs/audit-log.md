# Audit log: stability contract

Every authorization decision emits one structured log line on the `apparitor` logger.
This document freezes the schema from `0.1.0` as a stability contract. A failure in
`tests/unit/test_log_contract.py` is a breaking log-schema change; see the stability
policy below. For a runnable walk-through that configures the logger and emits, parses, and
verifies every contract line below, see [`examples/observability/`](../examples/observability/).

## Logger

A single `logging.getLogger("apparitor")` is shared across all modules (`engine.py`,
`mapping.py`, `fastmcp.py`, `a2a.py`). Levels used:

| Level | When |
| --- | --- |
| `INFO` | Contract lines (C1, C2, C3); adapter startup lines |
| `WARNING` | Operator-actionable conditions (mapping failure, PDP error, cache bypass, collapse guard) |
| `ERROR` / `exception` | Internal faults, adapter errors |

**Sensitivity:** subject ids are the decision principals and may be email addresses or
other user identifiers. Route the `apparitor` logger to a restricted sink accordingly.

## Contract lines (frozen from 0.1.0)

### C1: decision audit record

Emitted by `_log` in `engine.py` at `INFO` level for every authorization call that
produces a decision (skip paths are silent; see below).

**Format string:**

```
apparitor decision verdict=%s status=%s subjects=%s correlation=%s resources=%s fingerprints=%s latency_ms=%.1f
```

**Rendered example:**

```
apparitor decision verdict=allow status=success subjects=['alice@acme.com', 'travel-bot'] correlation=corr-42 resources=['files/read'] fingerprints=['3a9f1c20e741'] latency_ms=12.3
```

**Field table:**

| Field | Type | Semantics | Can be None? |
| --- | --- | --- | --- |
| `verdict` | `str` enum | Authorization outcome: `allow`, `block`, `human_review` | No |
| `status` | `str` enum | Evaluation path: `success`, `error` | No |
| `subjects` | Python-repr list of strings | Sorted, deduplicated subject **ids only** (no type); one entry per distinct principal | No |
| `correlation` | `str` or `None` | Value of `correlation_id` from the request context, rendered as the literal `None` when absent, never omitted | Yes (renders as `None`) |
| `resources` | Python-repr list of strings | Resource ids, positional per evaluation request; dual-principal = two entries (one per leg), duplicates expected | No |
| `fingerprints` | Python-repr list of strings | 12-character hex digests, positional per request (same order as `resources`) | No |
| `latency_ms` | `float`, always one decimal (`%.1f`) | Wall-clock time from first `perf_counter` to emit, in milliseconds | No |

**Notes:**

- `subjects=` is the Python repr of a sorted, deduplicated list of subject id strings.
  Under dual-principal evaluation this names both the user and the agent. The list is
  always sorted so parsers can rely on stable ordering.
- `correlation=` renders the literal string `None` (not omitted, not JSON `null`) when no
  `correlation_id` is present in the request context.
- `resources=` and `fingerprints=` carry one entry per `EvaluationRequest` sent to the
  PDP. A dual-principal call emits two entries even when the resource id is identical for
  both legs.
- C1 is **not** emitted on SKIP paths (empty tool-call list, mapper abstention on all
  calls). Silence is by design on skip; there is nothing to audit. SKIP paths emit no C1
  line; in practice verdict is `allow`|`block`|`human_review` and status is
  `success`|`error`.

### C2: batch denied-legs companion

Emitted in `_evaluate_batch` in `engine.py` at `INFO` level. Companion to C1 on
multi-request batches (the aggregate enforcement path, `/evaluations`) where the aggregate
verdict is not `allow`. The per-item `evaluate_each` path also uses a batch PDP call but
emits C3, never C2. C2 belongs to the aggregate enforcement path only.

**Format string:**

```
apparitor batch denied_legs=%s
```

**Rendered example:**

```
apparitor batch denied_legs=['user:alice@acme.com tool_call.execute files/delete', 'agent:travel-bot tool_call.execute files/delete']
```

**Field table:**

| Field | Type | Semantics | Can be None? |
| --- | --- | --- | --- |
| `denied_legs` | Python-repr list of strings | One entry per denied leg; each entry: `<subject.type>:<subject.id> <action.name> <resource.id>` | No (empty list not emitted; a non-ALLOW aggregate from `aggregate()` implies at least one decision was false, so `denied_legs` is never empty when C2 fires) |

**Notes:**

- C2 carries `type:id` in each entry (asymmetry with C1 `subjects=`, which carries id
  only). This lets an operator distinguish a user-grant deny from an agent-boundary deny
  at a glance.
- C2 never carries raw arguments or request context.
- C2 only fires on multi-request batches (`/evaluations`); single-request denies produce
  C1 only.

### C3: evaluate_each summary

Emitted in `_emit_each` in `engine.py` at `INFO` level. Advisory summary for
`evaluate_each` (per-item visibility filtering, e.g. `tools/list`). **Not an audit
record**: no subjects, resources, fingerprints, or correlation id.

**Format string:**

```
apparitor per-item decisions verdicts=%s latency_ms=%.1f
```

**Rendered example:**

```
apparitor per-item decisions verdicts=['allow', 'block'] latency_ms=8.4
```

**Field table:**

| Field | Type | Semantics | Can be None? |
| --- | --- | --- | --- |
| `verdicts` | Python-repr list of strings | One verdict string per call, positional | No |
| `latency_ms` | `float`, always one decimal (`%.1f`) | Shared batch latency in milliseconds | No |

**Notes:**

- C3 is advisory only. Do not rely on it for audit, alerting, or access-control decisions;
  use C1 for enforcement-path records.
- Verdicts in `evaluate_each` counters are indistinguishable from C1 enforcement decisions
  in the metrics sink; account for that when alerting on block rates.

## Timestamps and clock

The contract lines deliberately carry **no timestamp token**: the `logging.LogRecord`'s
`created` attribute (rendered via your formatter's `%(asctime)s`) is the time source, as
is standard for Python logging. Two consequences for deployments that keep these lines as
audit records.

- **Configure the formatter** on the `apparitor` logger's handler to emit an ISO-8601
  UTC timestamp (e.g. `%(asctime)s` with a UTC converter). A sink that stores only
  `getMessage()` without record metadata has no event time and cannot serve as an audit
  trail.
- The host's clock is the clock of record. Run NTP-disciplined clocks on enforcement
  points in regulated deployments.

## Parsing guidance

- List-valued fields (`subjects=`, `resources=`, `fingerprints=`, `verdicts=`,
  `denied_legs=`) are Python `repr` output using single quotes, not JSON. Parse them with
  `ast.literal_eval` rather than a JSON parser.
- Anchor on the prefixes `apparitor decision `, `apparitor batch `, and
  `apparitor per-item ` to identify contract lines; the suffix fields follow in order.
- Treat the rendered line as the interface. The log record `msg` / `args` structure is
  internal; `LogRecord.getMessage()` (the formatted string) is the stable surface.
- `latency_ms=` always has exactly one decimal place (`\d+\.\d`).
- `fingerprints=` entries match `[0-9a-f]{12}`.

## Fingerprint derivation

Each fingerprint is the first 12 hex characters of the SHA-256 over the canonical JSON
(`json.dumps(..., sort_keys=True, separators=(",", ":"))`) of the full `EvaluationRequest`
tuple (subject + action + resource including arguments + context). This is the same digest
as the ALLOW cache key.

**What the fingerprint covers depends on `redact_arguments`:**

- With `redact_arguments=False` (non-default): argument values are hashed in full, so the
  fingerprint uniquely identifies a specific call including its argument values.
- With `redact_arguments=True` (default): argument values are replaced with
  `"***redacted***"` before hashing, so the fingerprint covers the tool/resource/subject/
  action/context plus argument **key names** only. Two calls differing only in argument
  **values** will produce the same fingerprint.

This is a contract fact: do not rely on fingerprints to distinguish calls that differ only
in argument values unless `redact_arguments=False` is explicitly configured.

## What is deliberately never logged

- **Raw tool arguments.** Arguments are fingerprinted; the digest identifies a call
  without exposing possibly-sensitive argument values.
- **Tokens and credentials.** No bearer tokens, API keys, or session material ever appear
  in any log line.
- **Engine reasons toward the wire.** Refusals exposed to callers are generic
  (`"blocked by authorization policy"`); the rich reason stays in the operator log.
- **Subject types.** C1 `subjects=` carries ids only. Type information appears in C2
  `denied_legs=` entries.

**Treat the `apparitor` logger as sensitive.** Subject ids are the decision principals and
may be email addresses or other user identifiers. Route this logger to a restricted,
access-controlled sink and do not forward it to end users.

## Informational lines (not part of the contract)

Informational lines use the `apparitor: <message>` form (colon after `apparitor`); contract
lines use `apparitor decision|batch|per-item` (no colon). That delimiter difference is the
operator's separator. Informational lines are **not** part of the stability contract and
may change without notice.

| Prefix | Level | When |
| --- | --- | --- |
| `apparitor: metrics/log emission failed (verdict unaffected)` | ERROR | `MetricsSink` or logging raised; decision already returned |
| `apparitor: cache metric emission failed (verdict unaffected)` | ERROR | `record_cache` raised inside the decision path |
| `apparitor: mapping failed, blocking (%s)` | WARNING | `AuthZENConfigError` from mapper on aggregate path |
| `apparitor: mapping failed, blocking all items (%s)` | WARNING | `AuthZENConfigError` from mapper on per-item path |
| `apparitor: PDP error, resolved as %s` | WARNING | `AuthZENServiceError`; verdict resolved via `on_error` |
| `apparitor: unexpected internal error during evaluation` | ERROR | Unhandled exception in evaluation; blocked fail-closed |
| `apparitor: dual-principal evaluation always batches, …` | WARNING | `cache_enabled=True` with a dual-principal path |
| `apparitor: boundary collapse guard refused: %s` | WARNING | Resolved caller equals boundary subject |
| `apparitor: FastMCP middleware gating …` | INFO | Middleware startup |
| `apparitor: A2A executor gating agent.invoke for …` | INFO | Executor startup |
| `apparitor: FastMCP authorization middleware error (refusing)` | ERROR | Unhandled exception in FastMCP middleware |
| `apparitor: listing filter error (hiding all tools)` | ERROR | Unhandled exception during tools/list filtering |
| `apparitor: A2A authorization executor error (refusing)` | ERROR | Unhandled exception in A2A executor |
| `apparitor: refusal metric emission failed (verdict unaffected)` | ERROR | Metrics raised on the refusal path |
| `apparitor: authenticated A2A user has no user_name; refusing` | WARNING | A2A peer missing identity |
| `apparitor: no usable server label for prompt authorization; refusing` | WARNING | FastMCP missing server label for prompt |
| `apparitor: unusable prompt name for authorization; refusing` | WARNING | FastMCP bad prompt name |
| `apparitor: unusable skill id from skill_resolver; refusing` | WARNING | A2A bad skill id |
| `apparitor: access token has no usable <claim> claim; refusing (…allow_workload_subject…)` | WARNING | FastMCP: verified token has no usable `sub` (or configured claim) and `allow_workload_subject` not set; call refused |
| `apparitor: no authenticated subject for MCP request; refusing (…)` | WARNING | FastMCP: no token, no injected subject, and `allow_static_subject` not set; call refused |
| `apparitor: no authenticated subject for A2A invocation; refusing (…)` | WARNING | A2A: no authenticated peer identity, no injected subject, and `allow_static_subject` not set; call refused |

## Regulatory context (EU)

The schema can contribute evidence about apparitor's authorization function. Whether EU
obligations apply depends on the complete system, its intended use and the operator's role.
Retention, integrity, residency and access control are properties of the sink. This mapping
is not a conformity assessment or legal advice.

| Obligation | How the schema relates |
| --- | --- |
| **AI Act (Reg. (EU) 2024/1689) Art. 12, record-keeping.** A provider must design an applicable high-risk AI system with logging capabilities that enable appropriate traceability. | C1 can contribute evidence for apparitor's authorization function. It is not the complete high-risk-system log and the Act does not require every C1 field. Applicability depends on the complete system and intended use. |
| **AI Act Arts. 19 / 26(6), log retention.** Providers and deployers have separate duties for automatically generated logs under their control, normally at least **six months**. | Retention happens at the sink, not in apparitor. Determine the responsible role, applicable start date and any longer period required by Union or national law. |
| **AI Act Art. 14, human oversight.** | `verdict=human_review` records that a decision was escalated to a human. Who reviewed it and the outcome happen outside apparitor. Your review workflow must produce its own record and can join on `correlation` / `fingerprints`. |
| **GDPR (Reg. (EU) 2016/679), personal data in logs.** | `subjects=` ids and `denied_legs=` entries are personal data when they identify people. Establish the applicable lawful basis and purpose; prefer tenant-scoped pseudonymous subject ids where policy allows. Fingerprints are **pseudonymous, not anonymous** when someone can reconstruct the request tuple. |
| **GDPR Arts. 5(1)(e), 17, storage limitation and erasure.** | Define retention and erasure handling against the actual purposes and legal duties. Whether an Article 17(3) exception applies is deployment-specific. Pseudonymous subject references reduce exposure but remain personal data when re-identification is reasonably possible. |
| **GDPR Ch. V / data sovereignty.** | Routing the `apparitor` logger to a sink outside the EU/EEA is a personal-data transfer. If residency is a requirement, the log pipeline (not just the PDP) must stay in-region. |
| **NIS2 (Dir. (EU) 2022/2555) / DORA (Reg. (EU) 2022/2554).** | The decision log feeds detection and incident reconstruction (denied legs name which principal was stopped, fail-closed errors are visible at WARNING/ERROR). Integrity protection (append-only storage, tamper evidence) is a sink property; these lines carry no signatures. |

One known limitation to weigh for AI Act traceability: with the default
`redact_arguments=True`, the input data of a call is represented only by argument **key
names** inside the fingerprint (see above). Some obligations require reconstructing *what*
was attempted, not just *that* it was attempted, by whom, on which resource. Those
deployments must either set `redact_arguments=False` (weigh the GDPR minimization cost) or
keep input records in an adjacent system joined via `correlation`.

The high-risk application dates changed after the Act was originally published. See the
current role, scope and timeline notes in [eu-ai-act.md](eu-ai-act.md), and use
[compliance-evidence.md](compliance-evidence.md) for a privacy-bounded JSON evidence option.

## Stability policy

From `0.1.0` the contract lines C1, C2, and C3 are **append-only**: new `key=value`
tokens may be added at the **end** of a line in a future release. Renames, removals, and
semantic changes to existing tokens are breaking and require:

1. A `CHANGELOG.md` entry under **Changed** with the text **"Update log parsers"**.
2. A version bump per semantic versioning.

`tests/unit/test_log_contract.py` pins the documented grammar; a failure there means a
breaking change is in flight.

The unreleased JSON evidence path adds durable local persistence through
[`LocalAuditCollector`](collector.md) and tenant-separated ingestion and queries through
the [Observe reference](observe.md). It does not change the frozen C1/C2/C3 grammar.

**Out of scope (tracked, deferred):** operated deployment, retention and backups,
tamper-evident storage, and statutory compliance exports. See [ROADMAP.md](../ROADMAP.md).
