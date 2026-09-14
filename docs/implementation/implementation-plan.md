# Implementation plan

Updated: 2026-09-14
Integrated software baseline: `5319d7d404b3c7b04f9810df87ff2757421e6a45` (through PR #78).

This is the current order of work. [IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md)
owns integrated capability and qualification claims; the [backlog](backlog.md#current-work-order)
owns the small NOW/NEXT/DEFERRED queue. The older Core alpha/FSE2 plan is retained
[below](#historical-planning-snapshot) as history, not a competing active roadmap.

This update records the next development outcomes; it does not claim they are
implemented or start a new deployment, live campaign or customer integration.
Execution and publication authority belong to the assigned task, not to a backlog label.

## Current order of work

1. **Integrated foundation:** standalone Broker protection, Broker → Gateway
   continuity, selected Windows delivery and application credential adoption
   through PRs #67–70; subsequent simplification, Admin first access/layout/operator
   guide, onboarding alignment, targeted security fixes and audit export/package
   preflight through PR #77. Do not restart these as separate development projects.
2. **Integrated through PR #78 — BROKER-ADOPT:** let an adopter register and maintain its own .NET
   application through supported tooling, beyond the bundled `local-sample`.
3. **NOW — EVAL-DELIVERY:** prepare a versioned evaluation package with one
   documented success/recovery path and one proportionate convergence check.
4. **DEFERRED:** new integrations, platforms and enterprise mechanisms require
   a concrete consumer or defect; see the [backlog triggers](backlog.md#deferred-work-triggers).

Integrated software, synthetic tests, selected Windows service observations and
external-service qualification remain separate. Updating this plan does not repeat
or extend the exact-candidate qualifications recorded below.

## Integrated — supported onboarding of an adopter's application

The runtime already accepts explicit application registrations, and the SDK already
exposes `ProtectData`/`UnprotectData`. The original gap was supported administration:
the Windows delivery script installed `local-sample` and updated its executable hash.
BROKER-ADOPT adds supported register/inspect/update/revoke tooling and a distinct
.NET evaluation app, integrated through PR #78. Package `4a8eb70...` passed the
ordinary-account real-service proof; integration does not change its source identity
or establish complete exact-main qualification.

Deliver one small, administrator-operated path to register, inspect, update and
revoke a named application, reusing the existing configuration, policy and SDK.
The first outcome is one application-owned, per-Installation credential with the
Gateway disabled. It does not add an external authentication flow or retrieve a
vendor credential.

Completion requires:

- A .NET evaluation application distinct from the bundled sample can be registered
  and perform authorized protection/unprotection using only the published procedure,
  without hand-editing service settings or knowing repository internals.
- Registration uses explicit administrator-approved Windows SID, installed executable
  identity and exact operation/context grants. Preserve existing path, hash/publisher,
  IPC-peer and directory-ownership checks; never authorize a general-purpose host or
  let the application enroll or widen its own permissions.
- An explicit executable update preserves the application registration, Installation,
  keys and existing ciphertext. Revocation denies subsequent use without deleting
  protected data, keys or unrelated registrations. Invalid or interrupted configuration
  changes preserve the last valid policy and fail closed.
- One real-service proof on the declared Windows target uses an ordinary account,
  a new application process, restart, authorized update and revocation. Focused
  negatives cover a wrong executable/account/context and an invalid update; reuse
  existing IPC, cryptography and package-preflight tests rather than repeating their lab.
- Diagnostics are bounded and contain no plaintext credential or key. The guide
  distinguishes application-secret replacement, issuer revocation and Broker key
  lifecycle, and states the compromised-process and DPAPI recovery limits.

No new service, Admin UI, vault, policy framework, secretless proxy, Connector,
native/COM adapter or automatic key rotation is required. Prefer the narrowest
extension of existing Windows tooling; a new runtime primitive needs an observed
blocker and an explicit complexity checkpoint.

## NOW — versioned evaluation delivery

After BROKER-ADOPT converges, select the exact artifact and supported target; package
the existing software, concise setup/verification/recovery instructions, known limits
and provenance. Reuse historical and exact-source evidence only where applicable.
Run the [existing pre-alpha usability check](backlog.md#pre-alpha-usability-qualification)
once on the delivered candidate, including fresh browser access and actual Windows
package use when that package is included. Record implementation, verification/lab
and evidence effort separately before starting; this is not a general re-audit or
a new installer project. A source snapshot is not a tested binary delivery.

## Development and institutional distribution

This plan and the internal backlog belong to the development repository. The
[ApoCert distribution](https://github.com/ApoCert-it/secure-integration-platform)
has independent snapshot history, public capability documentation, a changelog and
source provenance. Its 11 Sep 2026 source snapshot is based on `b13e6ba...`; it
does not contain this internal plan or authorize a binary release. Development
updates are not mirrored automatically. A separately authorized institutional
update must select the public deliverables and preserve attribution and provenance;
private customer integrations, agent instructions and internal planning stay excluded.

## Integrated — independently usable Windows Local Broker

An identified, authorized .NET application must be able to use an Installation-local
key through the Broker without receiving that key. The path must work without a
Gateway, survive service restart and a supported service update, and expose an honest
lifecycle and backup/restore procedure within DPAPI's limits.

Use the existing Windows Service, local protection operations, policy and SDK.
The [local candidate guide](../user/local-broker.md) records implemented software,
focused tests and the single real-service result separately. After an earlier
non-elevated SCM access denial, the authorized elevated gate passed on exact software
candidate `3955fd0c3a5eccf816d44b0faba9a704227baa3d`. It proves same-candidate
install/start/Protect/restart/update/old-ciphertext verification and owned cleanup,
not ordinary-user use, cross-release compatibility or disaster recovery.
Freeze one small application example and its result before expanding the surface;
add a primitive only if the chosen case requires it. This is not a new vault or
workload-identity platform.

Completion requires the following observable properties on the chosen Windows target:

- The documented path provisions the required local state and completes the selected
  operation without Gateway enrollment, availability or an external credential.
- IPC authenticates both peers. The Broker verifies the application and authorizes
  the operation and context; the SDK verifies the Broker. Unauthorized applications,
  a false peer or a wrong operation/context are denied before key use or payload disclosure.
- The key remains under the Broker's service identity and is never returned through
  the SDK/IPC or exposed in logs. Document key creation, use, rotation/retirement and
  deletion, including their effects on already-protected data.
- Restart and the supported service update preserve required identity, keys, policy
  and protected state. Missing or inconsistent state is an explicit failure, not
  silent reinitialization or a newly generated replacement key.
- Backup/restore identifies what must be retained and proves the supported restore
  case. DPAPI-protected blobs alone are not a portable recovery package. Loss of the
  machine, service profile or necessary recovery material may make data unrecoverable;
  no cross-machine recovery or central recovery service is implied.
- A small SDK/sample and executable guide provide prerequisites, authorized setup,
  invocation, expected result, update/recovery and owned cleanup without requiring
  test-fixture knowledge or manual store edits. Reuse existing sample/tooling where useful.

The Broker holds Installation-local keys; vendor credentials remain exclusively on
the Gateway side. It is neither EDR nor HSM. Administrator/SYSTEM and code injected
into an authorized process remain residual threats. Plaintext legitimately returned
to a compromised application cannot be protected by keeping the key in the Broker.

The relevant existing decisions are [Named Pipe IPC](../adr/0003-named-pipe-ipc.md),
[local protection](../adr/0004-local-protection.md),
[application identification](../adr/0016-application-process-identification.md) and
[recovery](../adr/0014-recovery.md). The
[installer lifecycle contract](../adr/0017-msi-installation-provisioning.md) informs
state preservation; completing all M9 installer work is not a prerequisite for this
bounded service-update proof.

## Integrated — Broker to Gateway continuity

Complete the existing remote path without introducing a second client identity or
runtime. The candidate persists only authoritative Installation/credential lifecycle
metadata, renews a non-exportable CNG credential once inside the Gateway-owned window,
and resumes after service/process restart. It reuses the existing synthetic
Connector/service and the shared authentication, grant and Published-operation model.

A pending renewal is recorded before dispatch. After a lost response, a later explicit
application call first authenticates the pending credential with the Gateway: accepted
state is promoted without resending; otherwise the still-authoritative current
credential is checked before one renewal submission. The Broker never automatically
replays an application invocation. A response lost after dispatch, timeout/body
interruption, or post-dispatch 5xx is a bounded non-retryable
`gateway_outcome_ambiguous`. `ConnectionError` also remains ambiguous because it does
not establish the dispatch phase. DNS resolution and TLS-handshake failures remain
retryable only through a new explicit caller invocation; read-only policy probes retain
their retryable transport-failure result.

The focused gate shows Broker SDK → Gateway → Published Connector → Synthetic Provider,
same-Installation restart without activation reuse, single-flight renewal, authoritative
renewal recovery, explicit reconnection, ambiguous invoke denial, and expired/revoked/
ungranted denial before the provider effect. It uses real Core services and local CNG/
filesystem state behind an in-process HTTP fault fixture; it does not prove a Windows
Service, TLS socket, PostgreSQL, external service or ordinary-user path. Do not build a
general reconnect framework in anticipation of other consumers.
See [Installation identity](../adr/0008-installation-identity.md) and the
[shared Broker/Direct principal](../adr/0020-direct-gateway-client-principal.md).

## Integrated — target-specific distribution and operation

Selected host: Windows 10 Pro 22H2 x64 build 19045.6466. Deliver a self-contained
archive using the existing lifecycle/sample, with an explicit application-user SID,
runtime/dependency inventory and checksums (not signatures). One administrator-assisted
script coordinates ordinary-token checks, restart, update from integrated build
`56b6d9a...` and one real service → Gateway/PostgreSQL/Synthetic Provider path.
No new runtime, worker or renewal matrix is required. Artifacts and focused checks
can complete without elevation; actual service qualification cannot. Keep the
application invocation result distinct from SCM readiness and the historical gate.

This bounded gate passed on software `5ad048f169b5ba19d8d058d240a2c5029cce9703`;
[the observed results and limits](../user/local-broker.md#windows-delivery-observed-on-september-5-2026)
now replace preparation status. The baseline's non-elevated access failure remains
recorded; elevated baseline envelope preparation proves compatibility only. Independent
review and integration completed through PR #69; this gate is not repeated for adoption.

After the application paths work, select the actual Windows versions, architectures
and deployment context to qualify. Deliver an installable artifact, tested lifecycle
and a compatibility matrix describing what was actually exercised, with explicit
recovery and support limits. Publishing that artifact still requires separate authority.

A universal MSI, COM/native adapters, every Windows version, the whole M9 plan and
enterprise HA/DR are not prerequisites for the first local result. A target-specific
need can bring one of these forward only through an explicit scope decision, not an
assumed “production-ready” requirement.

## Scope and evidence boundaries

The current application-adoption result reuses `ProtectData`/`UnprotectData`: hidden
runtime credential input, private application-owned ciphertext, transient plaintext
use by the authorized app and replacement without recompilation. A pre-commit save
failure preserves the previous configuration. No key rotation or password change at
an external issuer is implied. The guide identifies the old constant/configuration
read to replace, issuer revocation and machine-loss recovery responsibilities.
Focused tests cover the sequence, input bound, tamper/context/ownership denial and
failed save. One separate task-owned real Windows standard account (not a member of
Administrators) closes that precise qualification gap; no repetition of the delivery
or Gateway laboratory. That [real-account result passed](../user/local-broker.md#application-credential-adoption-observed-on-september-6-2026)
on software `8909ab9...` with gate `9ab03c1...`; review and integration completed
through PR #70. BROKER-ADOPT addresses the remaining own-application tooling gap,
not a missing protection primitive.
There is no new vault, primitive, proxy, connector or claim that the application
never receives plaintext, and no CVD closure without integrating the actual adopter.

Maintain three distinct verification paths:

- The provider-neutral synthetic Core remains easy to evaluate through its
  [existing local pilot](../user/local-pilot.md).
- Windows/Broker demonstrates the installed-software boundary. Historical M0/M1,
  M3A and later standalone/delivery observations remain attached to their exact
  baselines; an adopter's application needs its own bounded acceptance result.
- FSE2 remains an optional pack and separate external-integration evidence. Its
  [current guide](../user/fse2-validation-status.md) and the authoritative status
  retain the offline/live distinctions. This work neither reopens that track nor
  requires another live call.

The differentiation hypothesis is a small set of authorized operations for distributed
Windows applications, with less credential distribution and manageable adoption cost.
Windows support alone is not a differentiation claim. SIP is not being expanded into
a general-purpose replacement for SPIRE, Aembit or Secretless. Customer-specific
integrations have separate private plans and authority; they are not public Core
dependencies or prerequisites for this outcome.

Do not add speculative Connectors, a universal SQL/HTTP proxy, `GetSecret`, mandatory
cloud, SPIFFE/WIMSE federation, continuous attestation, a mandatory driver/TEE or a
new identity/vault platform. A new primitive needs a demonstrated requirement from
the selected case; a new Connector needs concrete demand and separate authorization.

## Ownership, measurement and verification

One implementation owner carries EVAL-DELIVERY end-to-end from the integrated plan.
Estimate implementation, verification/laboratory and evidence separately; freeze
the visible result and essential negatives before coding. Do not split the result
into a chain of micro-PRs or writer/reviewer handoffs. Parallel work is useful only
for independent, disjoint outputs without competing changes to shared contracts.

Use the small sample to record adopter steps and, where useful, startup time, memory
and operation latency, with workload and machine context. These are measurements,
not invented thresholds or evidence of performance on untested Windows targets.
Do not build a new laboratory or production instrumentation solely for this evidence.

Use focused named tests while changing the affected surface, including positive and
negative IPC/policy, state-preservation and supported recovery cases. Review one
converged candidate and run the applicable gates in proportion to its risk. Keep
documentation-only checks to content/links, delta secret scanning and diff-check;
do not duplicate unrelated local runtime suites or SBOMs.

Iterate on distinct causal findings until the agreed outcome is met. Stop for a real
authority boundary, risk of data loss or a material architectural decision—not an
arbitrary commit or attempt count. Do not weaken authentication, policy, ACLs, DPAPI
isolation or cleanup to obtain a passing test. Update status only for results actually
proved, distinguishing candidate evidence from integration and release qualification.

## Historical planning snapshot

The following plan retains its original baseline, gate states and sequence. Its
“active”, “CURRENT”, “TARGET” and milestone labels describe that recorded period only.
They do not override the current order above or convert old TODO entries into PASS.

Updated: 2026-08-24
Recorded planning baseline: `97daa565f582d575da5d61665126c50ea52be3ed`

The status tables and gate outcomes below are planning snapshots, not current
qualification claims. In particular, the earlier 11-operation/no-live FSE2 snapshot
is superseded by the integrated PR #65 status and
[current pilot](../user/fse2-validation-status.md). Gate criteria remain references;
this note does not attest new gate outcomes or authorize publication.

Current summary status is in
[`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md), gates in
[`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md) and ordered slices in the
[`backlog`](backlog.md). Detailed history remains in the existing tags and reports.

### Planning principles

- a capability is CURRENT only when integrated into `main`; a release or external
  qualification also requires its own exact-head gate;
- synthetic, live lab, official-test and production are distinct states;
- optional packs depend on Core contracts; Core does not depend on cloud or
  vertical packs;
- no generic capability enters this phase without a reproducible Core golden-path
  or FSE2 gate blocker;
- a maintainer statement does not become repository evidence;
- attested baselines are not rewritten;
- there are only two active tracks: Core alpha and FSE2 Organization OfficialTest.

### Recorded baseline

| Area | Status | Current limitation |
|---|---|---|
| M0-M2 | Done | Foundations, Broker and Gateway integrated; historical live gates are not an installer release. |
| M3A | PASS live lab | M3B Azure remains unqualified. |
| M4/M5/M5.5 | Done | Connector lifecycle, Admin and Direct Gateway integrated; Direct sample key storage remains non-production. |
| Authentication foundation / Wave 1 | Integrated | Provider-neutral primitives and external modules do not automatically qualify an external service. |
| FSE2 Organization | Synthetic-qualified | 11 operations, dual JWT, S1 `contentCommitment`, distinct A1 mTLS and canonical PostgreSQL; no live calls. |
| Local PKCS12 / FSE2 vertical image | Integrated by PR #33, synthetic lab qualified | Optional `SecretValues=false` provider, offline importer, overlay and vertical image; custody and OfficialTest open. |
| Productization alpha | Governance candidate | Version/artifacts and golden path are candidates; ALPHA-LIC/SEC/DOC-04 are implemented on the branch but await review/integration. ALPHA-REL is not closed. |
| Legacy/enterprise | Deferred | MSI, native/COM, live cloud, HA/DR and production are not active tracks. |

PR #33 was merged by fast-forward onto exact main. General 6/6, M5/Admin 15/15,
PostgreSQL FSE2 1/1 zero skips, provider 30/30, architecture 42/42, provider-active
synthetic lab and security micro-review are PASS/GO within the attested scope. These gates
do not include real material, operational import or FSE2 calls.

### Track A — Core `0.1.0-alpha`

#### Outcome

A non-production, provider-neutral developer alpha with one golden path:

```text
Direct .NET
→ Gateway
→ Connector REST Published
→ Synthetic Provider
→ mock HTTPS/mTLS
→ sanitized response and metadata-only audit
```

#### Dependencies and parallel work

DOC-01 is the only initial common prerequisite. After DOC-01, these proceed in parallel:

- **Core documentation:** DOC-02 for architecture/security/deployment and DOC-03 for
  OpenAPI/API/generated types;
- **Core consumption:** ALPHA-REST, ALPHA-DIRECT and ALPHA-CLEAN;
- **productization:** ALPHA-VER may start without waiting for DOC-02/03; ALPHA-ART follows
  ALPHA-VER;
- **governance:** human decisions ALPHA-LIC and ALPHA-SEC are implemented in the ALPHA-GOV-REL slice and remain pending independent review/integration;
- **FSE2 documentation:** DOC-04 aligns the optional pack with the state integrated by
  PR #33, without executing or requiring FSE2-T01..T06.

ALPHA-ADOPT starts when the golden path is documented and repeatable: it requires
ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN and applicable Core documentation DOC-02/03.

ALPHA-REL is the final step and explicitly requires ALPHA-DOC-01, ALPHA-DOC-02,
ALPHA-DOC-03, ALPHA-DOC-04, ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-ADOPT,
ALPHA-VER, ALPHA-ART, ALPHA-LIC and ALPHA-SEC, plus green ALPHA-01..08 on the exact
release candidate. ALPHA-DOC-04 is a documentation-truth dependency only: it does not
require live `validate-cda` or FSE2-T01..T06. FSE2 OfficialTest qualification does not block
the Core alpha release.

#### Constraints

- FSE2 and vendor-specific packs do not enter the Core golden path;
- MSI, COM/C ABI, Azure live, HA/DR and stable API compatibility remain excluded;
- the raw Core export SHA is evidence for a single run. `ALPHA-ART` adds a normalized
  inventory digest because `generatedAtUtc` makes the raw manifest run-specific;
- no publication precedes independent review, integration and the ALPHA-LIC and ALPHA-SEC publication gate.

### Track B — FSE2 Organization OfficialTest

#### Outcome

The first outcome is `validate-cda` in the official test environment, with an authorized
synthetic dataset, exact configuration and redacted evidence. Attachment hash, create/replace and
status follow; they are not `validate-cda` prerequisites without new official evidence.

#### Integrated CURRENT

- optional Local PKCS12 pack, without generic secret retrieval and with
  `SecretValues=false`/deny-only slot;
- offline importer and synthetic path/CSR/ACL/custody guards;
- vertical image including `Healthcare.FSE2`, while the default Gateway Core
  image continues to exclude it;
- Compose overlay and provider-active synthetic lab;
- S1 `contentCommitment`, distinct A1 mTLS, CI and review within the synthetic scope.

#### TARGET still open

- operational access/import and verification of real custody;
- verified distinction between test access and software accreditation;
- any `ActivationHmacSecretReference` composed as a separate server-owned
  capability, never as generic secret retrieval by the certificate pack;
- bounded warning mapping for `validate-cda`;
- exact OfficialTest image/configuration and redacted operational driver;
- any live FSE2, `validate-cda`, create/replace or status call.

#### Candidate operationalization slice

The `FSE2-OFFICIALTEST-OPERATIONALIZATION` slice, still subject to exact-head gate and review, fixes
the canonical source for `validate-cda` only, the closed external plan, A1 mTLS/S1 authorization+integrity,
the zero-effect dry run and the Admin configure/propose/approve/publish/read-back workflow. It does not
import operational material, add Core primitives or make a live call. Its
authority uses exact server-side A1/S1 lookups, an authenticated publisher identical to the exact approver and
URI composition that preserves the OfficialTest prefix without accepting caller overrides.
Integration closes only the software tooling in step 6; steps 1-5 and 7-8 remain separate
operational gates.

#### Sequence

1. external intake: distinguish test access and software accreditation;
2. import/custody preflight outside Git;
3. composition of required server-owned capabilities;
4. public metadata, chain, S1 signing and A1 mTLS preflight without FSE2 network access;
5. bounded warning mapping required for `validate-cda`;
6. vertical image and exact OfficialTest configuration;
7. synthetic E2E from the same image/configuration;
8. `validate-cda` OfficialTest with an authorized synthetic dataset;
9. `attachment_hash` over exact file bytes;
10. authorized create/replace;
11. bounded/redacted status;
12. subsequent workflows only if included in the plan.

#### Gates and claims

FSE2-T01..T04 and T06 enable only the `validate-cda` official-test claim on the exact
attested configuration. FSE2-T05 enables only subsequent workflows actually
executed. Synthetic tests of the 11 operations do not become an 11/11 live claim. No
gate in this track implies production.

### Relationship between tracks

```text
DOC-01
  ├─→ ALPHA-DOC-02 ───────────────────────────────────┐
  ├─→ ALPHA-DOC-03 ───────────────────────────────────┤
  ├─→ ALPHA-REST ─────────────────────────────────────┤
  ├─→ ALPHA-DIRECT ───────────────────────────────────┼─→ ALPHA-ADOPT ───────┐
  ├─→ ALPHA-CLEAN ────────────────────────────────────┘                       │
  ├─→ ALPHA-VER ─→ ALPHA-ART ────────────────────────────────────────────────┤
  ├─→ ALPHA-LIC + ALPHA-SEC ─────────────────────────────────────────────────┤
  └─→ ALPHA-DOC-04 (truth only; no validate-cda/FSE2 gates) ──────────────────┘
                                                                                └─→ ALPHA-REL + ALPHA-01..08

Independent Track B: intake/custody/composition → offline preflight → exact synthetic E2E
                                                → validate-cda → hash/create/status
```

The two tracks can advance independently. An FSE2 problem does not block Core alpha
unless it demonstrates a general security defect. A new Core abstraction requires
a concrete blocker and test. DOC-04 does not convert FSE2 gates into Core gates: it only
keeps the optional pack documentation truthful.

### HISTORICAL and deferred work

The original roadmap used M0-M9. The M6/M7 names are ambiguous because the authentication
foundation was brought forward ahead of legacy adapters. Historical tags and reports remain
immutable, but new work and statuses use ALPHA/FSE2 IDs.

Legacy beta, other providers, other verticals and enterprise/production remain deferred
backlog, not active tracks. This plan neither estimates nor starts them.
