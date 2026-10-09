# Compliance evidence records

`apparitor.audit` creates bounded JSON records for authorization observations. The schema
is useful input to a control or legal assessment; a valid record is not an attestation of
compliance, execution, identity, policy correctness, or log integrity.

## Host integration

Create `AuditMetadata` at the trusted request boundary. `event_id` identifies the host
request and may be shared by several per-item records; each emitted record receives a new
`evidence_id`. Values ending in `_ref` must be opaque, tenant-scoped references generated
by the host. Do not pass emails, account names, raw resource paths, prompts or arguments.

```python
from apparitor.audit import AuditMetadata, JsonLinesAuditSink, audit_metadata_scope

metadata = AuditMetadata(
    event_id="request_01J...",
    tenant_ref="tenant_hmac_...",
    principal_refs=("principal_hmac_...",),
    request_refs=("operation_hmac_...",),
    policy_id="agent-access",
    policy_version="sha256:...",
)

engine = AuthorizationEngine(config, audit_sink=JsonLinesAuditSink(stream))
with audit_metadata_scope(metadata):
    result = await engine.evaluate_requests(requests)
```

An engine integration can send `make_decision_evidence(...)` to an `AuditSink`.
`JsonLinesAuditSink` writes one compact JSON object per line to a host-owned text stream;
it does not provide file opening, locking, rotation, signing, upload, retention or access
control. Sink failures must never turn an authorization decision into an allow.
The engine treats emission as best effort and increments `engine.audit_failures`; monitor
that counter because a successful authorization with a failed sink has no evidence record.

## Record semantics

`event_kind` distinguishes aggregate enforcement decisions, per-item filtering decisions,
mapping failures, boundary refusals and cancellations. `request_count` records cardinality only. AuthZEN
subjects, actions, resources, properties and context are never copied by the builder.
The fixed `not_collected` list makes the absence of credentials, direct principal IDs,
protected attributes, content, raw arguments and raw context machine-readable.

`policy_id` and `policy_version` are optional but atomic: provide both or neither. They
describe the policy reference asserted by the host, not proof that a named policy was
loaded. `cache_status` is an observed engine path (`hit`, `miss`, `not_applicable`, or
`unknown`). `error_code` is a bounded classification, not a free-form exception message.
`oversight_status` reports only what the trusted host supplies.

Decision evidence starts with `execution_status=not_observed`. Authorization happens
before execution and cannot imply `not_started`, `succeeded`, or `failed`.
`with_execution_outcome(...)` returns a new `event_kind=execution_outcome` observation with
a new `evidence_id`, preserving the request's `event_id` for linkage. This keeps execution
observations distinct from authorization-decision counts.

`summarize_evidence(records)` deduplicates by `evidence_id` and reports duplicate IDs. It
keeps aggregate authorization decisions, per-item decisions and execution outcomes in
separate denominators. It counts successful policy denials separately from evaluation
faults, human-review verdicts, cache paths, oversight states, observed execution outcomes,
latency samples and missing policy/principal/request references. The `authorization_faults`
total additionally includes pre-evaluation mapping failures, boundary refusals and authorization cancellations
without adding them to the decision denominator. The Observe error count uses this total.
Skipped observations are counted separately and excluded from decision and latency denominators.
Missing-reference counts
are an evidence-profile completeness check; those fields are not universally mandated by
the laws below.

These are operational authorization metrics. They are not measurements of model accuracy,
reliability, disparate impact, demographic parity, safety-evaluation performance or a
statutory critical incident. Those assessments require external evaluation artifacts and,
where legally justified, carefully governed data. Link such artifacts with opaque request
or outcome references; do not add protected attributes or raw evaluation data to this log.

## U.S. state status and evidence examples

Current to **9 October 2026** and intentionally non-exhaustive. “Proposed” means the cited
measure had not become law by this cutoff. State requirements are use-case and role
specific; they do not create a universal event schema or mandate generic block-rate
metrics.

Coverage focuses on material operational evidence regimes. It is not a fifty-state index
of every AI-related law and excludes most biometric-only, deepfake, election,
intellectual-property, publicity-right, takedown and government-procurement measures.
The California AI Transparency Act is included because it imposes broad operational
content-provenance and detection duties, rather than because this catalog covers the
whole synthetic-media field.

The review also checked the Massachusetts Legislature's current AI/automated-decision
proposals. No statewide Massachusetts measure with comparable enacted provider/deployer
evidence duties was added at this cutoff; proposal text is not presented as law. Refresh
the catalog before relying on it for a new deployment.

The machine-readable companion [compliance-jurisdictions.json](compliance-jurisdictions.json)
records actor, applicability, status and effective date separately. The table uses its stable
IDs so documentation checks can detect omissions.

| Catalog ID and measure | Actor and applicability | Status / effective date | Required evidence family | apparitor contribution and external gap |
| --- | --- | --- | --- | --- |
| `ca-ab-2013` — California [AB 2013](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240AB2013) | Developers of publicly available generative AI in statutory scope | Enacted; effective 1 January 2026 | Training-data transparency disclosures | External only: authorization events contain no training-data provenance, ownership, licensing or personal-data description. |
| `ca-sb-53` — California [SB 53](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202520260SB53) | Qualifying large frontier developers | Enacted; effective 1 January 2026 | Published safety framework; specified critical-incident reports | Linkage only: a denial or error is not automatically a statutory incident; evaluations and incident facts remain external. |
| `ca-sb-813` — California [SB 813](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202520260SB813) | Independent verification organizations assessing AI systems or models under the state framework | Enacted 9 September 2026; ordinary 1 January 2027 effective date inferred, enrolled-text clause unverified | Certification, independence, assessment methodology and findings | External only: authorization-event metrics are neither an independent safety evaluation nor certification of a system or assessor. |
| `ca-ab-1405` — California [AB 1405](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202520260AB1405) | AI auditors subject to the state registry and its standards | Enacted 9 September 2026; ordinary 1 January 2027 effective date inferred, enrolled-text clause unverified | Auditor registration, independence, transparency and integrity evidence | External only: conflicts, qualifications, audit design and conclusions require the auditor's governed artifacts. |
| `ca-sb-942-ab-853` — California [AI Transparency Act, amended by AB 2713](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202520260AB2713) | Covered generative-AI providers and specified platforms or capture-device manufacturers | First implementation phase began August 2026; exact day unresolved; AB 2713 signed 30 September 2026; ordinary 1 January 2027 effective date inferred, enrolled-text clause unverified | Detection tool, manifest/latent content disclosures and role-specific provenance controls | Linkage only: detection results, provenance payloads, content facts and platform controls are external artifacts. The author's 3 August press-release title says “August 1,” while his 12 August newsletter identifies August 2; the catalog leaves the exact effective date unset and records both reported dates until the consolidated statutory text can be verified. |
| `ca-sb-243` — California [SB 243 / Chapter 677](https://leginfo.legislature.ca.gov/faces/billHistoryClient.xhtml?bill_id=202520260SB243) | Operators making covered companion-chatbot platforms available to California users | Enacted 13 October 2025; effective 1 January 2026 | AI/nonhuman disclosures, minor safeguards, reminders, self-harm protocols and statutory platform reports | Linkage only: disclosure delivery, safeguards and reports remain external. Never put conversation or health content in authorization evidence. |
| `co-sb-26-189` — Colorado [SB 26-189](https://leg.colorado.gov/bills/sb26-189) | Covered-ADMT developers and deployers in consequential decisions | Enacted; central duties start 1 January 2027 | Documentation, notices, adverse-outcome explanation, meaningful review, three-year compliance records | Partial linkage: inputs, consumer explanation, discrimination analysis and reconsideration remain external. |
| `il-hb-3773` — Illinois [HB 3773 / PA 103-0804](https://www.ilga.gov/ftp/legislation/103/BillStatus/HTML/10300HB3773.html) | Employers using AI in recruitment or enumerated employment decisions | Enacted; effective 1 January 2026 | Employee notice and employment-discrimination controls | Linkage only: notice delivery and protected-class effect analysis remain external. |
| `ny-raise-s8828` — New York RAISE amendment [S 8828](https://www.nysenate.gov/legislation/bills/2025/S8828) | Frontier developers within statutory thresholds | Enacted 27 March 2026; operative 1 January 2027 | Safety framework and critical-incident reporting | Linkage only: model evaluations and incident evidence remain external. This is enacted law with a future operative date, not a proposal. |
| `tx-hb-149` — Texas [HB 149](https://capitol.texas.gov/billlookup/BillSummary.aspx?Bill=HB149&LegSess=89R) | Role- and use-specific government, health, developer and deployer provisions | Enacted; effective 1 January 2026 | Interaction disclosures and prohibited-use controls | Partial linkage; no universal block-rate mandate. Notices, purpose, biometric facts and discrimination analysis remain external. |
| `tx-sb-1188` — Texas [SB 1188](https://capitol.texas.gov/tlodocs/89R/billtext/html/SB01188F.HTM) | Practitioners using AI for diagnostic or treatment recommendations and covered EHR entities | Enacted 20 June 2025; effective 1 September 2025 (specified storage transition applies 1 January 2026) | Practitioner review, patient AI-use disclosure and EHR access/safeguard controls | Linkage only: clinical review, disclosure and EHR evidence stay in governed clinical systems; authorization logs must not contain protected health information. |
| `ut-sb-226` — Utah [SB 226](https://le.utah.gov/~2025/bills/sbillenr/SB0226.pdf) | Covered consumer-transaction suppliers and regulated-service providers using generative AI | Enacted; effective 7 May 2025 | AI-interaction disclosures and consumer-protection controls | Linkage only: proof of disclosure delivery and regulated-service records remain external. |
| `ut-hb-452` — Utah [HB 452](https://le.utah.gov/~2025/bills/hbillenr/HB0452.pdf) | Suppliers of covered mental-health chatbots made available to Utah users | Enacted 25 March 2025; effective 7 May 2025 | AI/nonhuman disclosures, personal-information controls, and development, deployment and monitoring policies | Linkage only: disclosure and policy evidence remain external. Never copy user input or health content into authorization records. |
| `ny-s-1169b` — New York AI Act [S 1169B](https://www.nysenate.gov/legislation/bills/2025/S1169/amendment/B) | Proposed high-risk AI developer/deployer framework | **Proposed**; passed Senate 3 June 2026, not enacted by cutoff | Independent discrimination, accuracy/reliability and risk-management audits | External evaluation artifacts; not derivable from authorization totals. |
| `ny-a-9654` — New York AI Civil Rights Act [A 9654](https://www.nysenate.gov/legislation/bills/2025/A9654) | Proposed covered-algorithm developer/deployer framework | **Proposed**; in Assembly committee at cutoff | Audited pre-deployment evaluation, post-deployment impact assessment, bias and real-world performance comparison | External governed evaluation data, especially for protected-class analysis. |
| `nyc-ll-144` — NYC [Local Law 144](https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page) | Employers and employment agencies using covered AEDTs for NYC hiring or promotion | Local law; effective 1 January 2023, enforced from 5 July 2023 | Annual independent bias audit, published results and candidate/employee notice | External only: selection rates, impact ratios, auditor independence and notices are not authorization metrics. Included separately because it is local. |

Use `event_id`, policy references and opaque outcome references to join
apparitor evidence to the system-of-record. Maintain legally required notices, assessments,
incident facts and consumer responses in the responsible workflow; do not expand this
authorization record with protected attributes or raw personal data.
