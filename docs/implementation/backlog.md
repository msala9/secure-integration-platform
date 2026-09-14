# Backlog ordered by outcome

Updated: 2026-09-14
Integrated software baseline: `b13e6ba781a90d331836d37ec363baf27248737f` (through PR #77).

This is the work queue, not another capability dashboard.
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md) owns integrated status;
the [implementation plan](implementation-plan.md#current-order-of-work) explains the
outcomes and boundaries. Historical slice tables are preserved [below](#historical-backlog-snapshot).

## Current work order

| Priority | Outcome | Start condition | Completion criterion |
|---|---|---|---|
| Integrated through PR #67 | Independently usable Windows Local Broker | Local software and focused tests converged; one exact-candidate elevated service gate passed. | Identified .NET app uses an Installation-local key without receiving it or requiring a Gateway; mutually authenticated IPC and application/operation/context policy; restart and same-candidate update preserve state; tested DPAPI-bounded backup/restore and a small executable sample/guide. |
| Integrated through PR #68 | Broker → Gateway continuity | Standalone local result integrated; remote fault cases frozen. | In-process evidence: enrollment, Published invocation, same-Installation restart, single-flight renewal, revocation/expiry/grant denial, explicit reconnection and authoritative recovery after interruption, with no automatic replay of uncertain application mutations. |
| Integrated through PR #69 | Target-specific distribution and operation | Bounded real-service qualification passed on software `5ad048f...`, Windows 10 Pro 22H2 x64 19045.6466. | Package, non-elevated use on an Administrators-member account, exact two-build envelope compatibility, restart/rejected-update and real-service → Gateway/PG outage recovery observed. No broader Windows, live renewal/DR or production claim. |
| Integrated through PR #70 | Remove per-Installation hardcoding/plaintext storage | User approved extending the existing small sample; no new primitive or proxy. | Runtime input, ciphertext-only save, transient authorized use, new execution and safe replacement; short English guide and real non-Administrators-account proof. Focused tests and account gate PASS on software `8909ab9...` / gate `9ab03c1...`; candidate subsequently reviewed and integrated. |
| Integrated after PR #71 | Admin consolidation and targeted security/delivery controls | Included in the software baseline above. | First access, responsive layout, UTC dates, operator guide, Broker/Direct onboarding alignment, bounded IPC admission, Azure readiness read, tenant audit export and package preflight are integrated; not an assertion of production readiness. |
| NOW — BROKER-ADOPT | Register and maintain an adopter's own .NET application | Existing Broker/SDK protection and sample adoption are integrated; local candidate tooling and the distinct evaluation app are implemented on the branch. | Supported administrator tooling for explicit registration, inspection, executable update and revocation; no manual service-configuration edits. One ordinary-account real-service proof covers use, restart, old-ciphertext preservation and denial after revocation. |
| NEXT — EVAL-DELIVERY | Versioned, usable evaluation package | BROKER-ADOPT converged; artifact/target and publication scope selected. | One concise setup/verification/recovery guide and the existing pre-alpha usability check on the delivered candidate; source/manifest provenance, known limits and proportionate release checks. No new universal installer. |
| DEFERRED | Broader surfaces and additional integrations | A concrete requirement or observed defect, explicit scope and an owner; not hypothetical future reuse. | Define a bounded outcome and relevant negatives before promoting work. Use the triggers below; no new framework or laboratory by default. |

A prerequisite is not evidence of completion. Candidate evidence remains distinct from
integrated capability and live qualification. Historical Windows PASS-LIVE results stay
attached to their exact software commit; the continuity candidate is synthetic and does
not replace that real-service result.

## Deferred-work triggers

- **MSI/COM/native adapters or additional Windows targets:** a selected adopter/deployment
  needs that exact surface after the small .NET path works. Qualify only the requested
  artifact/compatibility slice; do not pull the whole M9 plan into NOW.
- **Additional cloud deployments, federation, attestation, drivers/TEE or providers:** a
  demonstrated requirement cannot be met safely with existing boundaries. A mandatory
  cloud, generic identity/vault platform or universal SQL/HTTP proxy is not planned.
- **New Connectors or customer pilots:** concrete demand and explicit authorization.
  Private integration plans remain outside the public repositories and do not
  become dependencies of the provider-neutral adoption path.
- **Untrusted Connector execution:** a concrete need to load third-party code outside
  the operator's trust boundary. Current in-process modules are trusted code; the
  capability boundary is not a sandbox. Do not build process isolation speculatively.
- **FSE2:** reopen only for a concrete requirement or observed defect with its own
  authorization. Existing offline and partial live qualifications remain unchanged;
  FHIR's undetermined 500 and unqualified publication are not prompts for speculative
  fixes or live retries.
- **Enterprise recovery/HA/DR and broad performance qualification:** a real operating
  target, workload and recovery objective. DPAPI context loss is not solved by
  promising recovery without recovery material.
- **Institutional distribution, tag or release:** explicit publication authority and
  the applicable converged checks. The ApoCert source snapshot is not an automatic
  mirror of development main; internal plans, agent instructions and private
  integrations stay excluded. No tag or release is authorized by this queue.

No `GetSecret`, copied vendor credentials, mandatory new identity platform or
additional abstraction is justified solely by an item being deferred.

The integrated standalone software has targeted Broker/SDK/storage evidence and one passing
[service verification entrypoint](../user/local-broker.md#one-real-service-verification-entrypoint)
on exact software candidate `3955fd0c3a5eccf816d44b0faba9a704227baa3d`.
That result covers elevated service lifecycle and same-candidate update only.
Later PR #69/#70 observations separately cover selected cross-build compatibility
and ordinary-account adoption; they do not establish general Windows compatibility
or disaster recovery. See the exact scopes in the implementation dashboard.

## Delivery and verification

One owner completes the next outcome from the integrated plan. Estimate implementation,
verification/lab and evidence separately. Use focused verification during causal
iterations and one final proportionate review; no artificial commit budget or series
of micro-PRs. Parallelize only independent outputs without competing product changes.

Measure adopter steps and useful startup/memory/latency observations through the small
sample, not a new laboratory or invented pass thresholds. Keep historical evidence
unchanged, avoid unrelated local suites/SBOM duplication and do not mark a candidate
result integrated or released before it is.

### Pre-alpha usability qualification

Before the next evaluation release, qualify the delivered candidate through the public
entrypoints, once at convergence. The institutional source snapshot does not close
this package-level check. A green component suite is not a substitute for
an adopter being able to enter and use the product. The Admin preview exposed two
gaps: the browser suite authenticated by API before opening the page, and its
container shared the Gateway network instead of using the host-published port.
These tests remain useful but do not prove first access from the adopter's browser.

Use the existing scripts and samples for four short checks; do not build a new lab:

- **Core:** clean candidate, only the documented Docker-first prerequisites,
  published commands, first successful call and cleanup. The developer path with
  a preinstalled SDK and `-SkipBuild` is a separate proof.
- **Admin:** fresh browser session through the host-published URL, UI login,
  supported guided workflow with distinct roles, reload/resume, logout and login.
  Inspect the dense pages at desktop and narrow widths; check keyboard access,
  visible actions, table scrolling and unambiguous dates. Do not pre-login by API
  or treat axe alone as a layout test.
- **Recovery:** one representative interrupted setup, repeated supported Stop and
  a successful new start. Preserve foreign resources; reuse existing failure
  tests rather than reproducing their entire matrix.
- **Windows, when distributing the Broker package:** install the actual candidate
  package on the declared Windows target, register the separate evaluation application
  through the supported adopter path, use it from an ordinary account in a new
  process, restart and verify reuse/update/revocation. A
  resumed historical installation is not fresh-package evidence.

Completion requires usable success and recovery without SQL, internal fixture
setup or manual repairs, plus the applicable existing CI/security gates on the
converged candidate. Record only the artifact, target, outcome and any unresolved
blocker. This is a release check, not a full rerun after every UI edit, and it does
not claim zero defects. Optional FSE2 qualifications remain separate; no new live
campaign, external accreditation or production access is required by this check.

## Historical backlog snapshot

The following tables retain their original slice states and dependencies, including
TODO, BLOCKED and candidate PASS entries. They are not today's execution queue or a
retroactive gate decision. Their “active” and “P0” labels describe the recorded period.

Updated: 2026-08-24
Recorded planning baseline: `97daa565f582d575da5d61665126c50ea52be3ed`

This file preserves recorded slice and gate states; it is not a second current
capability dashboard. Later integrated FSE2 work supersedes the earlier validate-only
targets: see [current status](../../IMPLEMENTATION_STATUS.md) and the
[current pilot](../user/fse2-validation-status.md). Do not infer publication approval
or new exact-head qualification from a historical `Closed` or `PASS` entry.

This backlog records the two planned tracks. `Todo` does not authorize out-of-scope
work; `BLOCKED_EXTERNAL` does not authorize unsafe workarounds. Gates and claims are defined
in [`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md).

### P0 — Core `0.1.0-alpha`

| ID | Outcome | Status | Dependency | Gate | Does not prove |
|---|---|---|---|---|---|
| ALPHA-DOC-01 | Reconcile governance, scope, backlog and DoD with PR #33 on exact main. | In progress | Exact main and preserved dirty truth source | ALPHA-05 | Complete architecture/security, API parity or FSE2 runbook. |
| ALPHA-DOC-02 | Align architecture, security and deployment boundaries, including relevant PostgreSQL/audit claims and traceability. | Todo | ALPHA-DOC-01 | ALPHA-04/05 | Code changes, threat remediation or production qualification. |
| ALPHA-DOC-03 | Make OpenAPI, API docs and generated types consistent with actual routes and parity tests. | Surface sufficient (authorized baseline) | ALPHA-DOC-01 | ALPHA-05 | Stable APIs or future backward compatibility. |
| ALPHA-DOC-04 | Align FSE2 documentation with exact main and separate synthetic, OfficialTest and production. | Candidate truth-aligned | ALPHA-DOC-01 and integrated PR #33 status | ALPHA-05; no FSE2 gate | Real custody, import, OfficialTest calls or FSE2-T01..T06 PASS. |
| ALPHA-VER | Derive one `0.1.0-alpha.1` version for assemblies, packages, Admin, OpenAPI, images and manifests; no `1.0.0` product default. | Closed (candidate) | ALPHA-DOC-01 | ALPHA-06/08 | Publication or API stability. |
| ALPHA-REST | Consolidate one Published `sample-secure-service` with Synthetic Provider, API key+mTLS, mock and consistent tutorial. | Closed (authorized baseline) | ALPHA-DOC-01 | ALPHA-02/03 | Support for other Connectors or real providers. |
| ALPHA-CLEAN | Prove clean clone and one quickstart with cleanup/canary on an unprepared machine. | Closed (authorized baseline) | ALPHA-DOC-01 | ALPHA-01/02 | Installer, Azure live or production operations. |
| ALPHA-DIRECT | Document and test Direct .NET as an evaluation integration, with explicit key-storage limitation. | Closed (authorized baseline) | ALPHA-DOC-01 | ALPHA-03/08 | Production-grade SDK or native/COM support. |
| ALPHA-ADOPT | Have a second user complete enrollment→publish→grant→invoke using only public documentation. | PASS — independent adopter simulation | ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-DOC-02, ALPHA-DOC-03 | ALPHA-03 | Market fit, support SLA or production adoption. |
| ALPHA-ART | Produce archive/checksum/SBOM/vulnerability inventory and add a normalized Core export inventory digest separate from the raw run-specific manifest. | Closed (candidate) | ALPHA-VER | ALPHA-06 | Absolute binary reproducibility, release signing or production provenance. |
| ALPHA-LIC | Apply the path-based MPL-2.0/Apache-2.0 decision, texts, metadata, artifact binding and validator. | Candidate implemented, pending independent review/integration | ALPHA-DOC-01; legal/business decision received | ALPHA-07 | Publication GO, trademark grant or license for external repositories. |
| ALPHA-SEC | Apply security contact, Contributor Covenant 3.0 and DCO 1.1 without CLA. | Candidate implemented, pending independent review/integration | ALPHA-DOC-01; maintainer/legal decision received | ALPHA-07 | Certification, SLA or enterprise security support. |
| ALPHA-REL | Prepare release notes/known limits and rerun ALPHA-01..08 on the exact candidate; tagging and publication require a subsequent slice/authorization. | NOT CLOSED | ALPHA-DOC-01, ALPHA-DOC-02, ALPHA-DOC-03, ALPHA-DOC-04 (truth alignment only), ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-ADOPT, ALPHA-VER, ALPHA-ART, ALPHA-LIC, ALPHA-SEC | ALPHA-01..08 | Production readiness, FSE2 qualification, tagging, publication or automatic merge. |

`P3-CORE-EXPORT-DIGEST` is **Closed (candidate)**. The raw manifest SHA remains evidence
for a single run because it includes `generatedAtUtc`; `normalizedInventorySha256` separately
covers source commit, file count and path/byte/SHA-256 inventory in ordinal order,
with a canonical UTF-8 payload without BOM. The finding does not reinterpret historical raw SHAs.

`NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT` is recorded as a known non-blocking
follow-up. This slice does not change UI behavior, CSS or Axe thresholds; only the public fixture hostname is aligned to the reserved `.test` domain.

DOC-02/03, ALPHA-REST/DIRECT/CLEAN, ALPHA-VER, DOC-04 and human blockers can
proceed in parallel after DOC-01. ALPHA-REL requires DOC-04 only to
describe the optional pack truthfully: it does not require live `validate-cda` or
FSE2-T01..T06. FSE2 gates are not ALPHA-REL dependencies, and a Track B blocker does not
block Core alpha unless it reveals a general Core security defect.

### Parallel P0 — FSE2 Organization OfficialTest

FSE2-PROV and FSE2-PACK are no longer candidates outside main: PR #33 integrated the
Local PKCS12 provider, importer, overlay and vertical image and qualified them synthetically. The
slices below cover only the remaining path to OfficialTest. The pack remains
`SecretValues=false`; generic secret retrieval remains deny-only.

| ID | Outcome | Status | Dependency | Gate | Does not prove |
|---|---|---|---|---|---|
| FSE2-INTAKE | Distinguish and verify test access, applicable software accreditation, authorized plan and public/redacted inventory outside Git. | BLOCKED_EXTERNAL | Organization input | FSE2-T01 | Production accreditation or material validity/custody. |
| FSE2-CUSTODY | Perform preflight and operational import outside Git with verified paths, ACLs, principal, chain, fingerprints and A1/S1 separation. | BLOCKED_EXTERNAL | FSE2-INTAKE, authorized material | FSE2-T02 | HSM/KMS equivalence, production rotation/revocation or FSE2 calls. |
| FSE2-ACTIVATION-COMPOSITION | Compose A1 certificate-use mTLS and the same S1 on both authorization/integrity slots, without generic secrets. Any future activation HMAC remains a separate server-owned capability only if required by the exact environment. | Candidate implemented for validate-cda; pending exact-head CI/review | Exact provider revisions and configuration authority | FSE2-T02 | Generic secret retrieval, `GetSecret`, real material or FSE2 calls. |
| FSE2-WARN | Map warnings required for `validate-cda` to bounded/allowlisted technical codes and discard raw text. | Todo | Frozen official source/plan | FSE2-T03/06 | Completeness of all responses or status workflows. |
| FSE2-DRIVER | Fix the exact OfficialTest Connector/binding/configuration for `validate-cda` only and a vertical provisioner with protected plan, redacted output and existing Admin surfaces. | Candidate implemented; pending exact-head CI/review and vertical image deployment | FSE2-CUSTODY, FSE2-ACTIVATION-COMPOSITION | FSE2-T03 | Connectivity, operational material or OfficialTest qualification. |
| FSE2-OFFLINE | Run synthetic E2E from the same image/configuration intended for OfficialTest, including zero-network negatives. | Todo | FSE2-WARN, FSE2-DRIVER | FSE2-T03 | Live call, accreditation or official response. |
| FSE2-LIVE-VAL | Run `validate-cda` OfficialTest with an authorized synthetic dataset and redacted evidence. | BLOCKED_EXTERNAL | FSE2-T01/T02/T03 and operational authorization | FSE2-T04/06 | Create/status, 11/11 live or production. |
| FSE2-HASH | Compute `attachment_hash` over exact input-file bytes for create/replace and cover file ≠ multipart with regression tests. | Candidate implemented, pending exact-head CI/review | Frozen ministerial hash definition and operational addendum | FSE2-T05 | `validate-cda`, live create/replace or OfficialTest qualification. |
| FSE2-STATUS | Map only bounded/redacted technical status outcomes and declare persistence limitations. | Product path offline candidate; pending exact-head CI/review | Durable correlation and frozen workflow plan | FSE2-T05/06 | Live status. |
| FSE2-LIVE-WF | Execute create/replace and status only if authorized, with verified hash and outcomes. | Todo | FSE2-HASH, FSE2-STATUS | FSE2-T05/06 | All 11 operations live-qualified or production. |
| FSE2-DUR | Cross-process/cross-node workflow persistence for `create + get-status-by-workflow`. | Integrated on exact main; product vertical E2E candidate PASS | Migration 0018 and authorized bridge | `FSE2_DUR_*` PostgreSQL 18 + final exact-head gate | No clinical data, Admin read-back, retention or OfficialTest/production qualification. |
| FSE2-HUMAN | Implement Human Actor only with an authorized official requirement and plan. | Deferred | Future specification and authorization | Future gate | Organization profile or production Human Actor. |

`FSE2-HASH` and `FSE2-STATUS` are not prerequisites for `validate-cda`. They become necessary
only for authorized create/status claims.

### Phase stop list

Until the alpha and first `validate-cda` are closed, do not start or authorize:

- new generic Core capabilities without a reproducible blocker;
- new vertical Connectors;
- other cloud providers;
- MSI;
- COM/C ABI;
- generic refactors not required by an observable defect;
- fuzzing or performance as a phase claim;
- HA/DR;
- marketplace;
- production claims;
- automatic merges.

Explicitly unauthorized claims are listed in the
[`scope`](0.1.0-alpha-scope.md#unauthorized-claims).

### Deferred outside the active tracks

Legacy distribution, other providers/verticals, production supply chain, enterprise
operability and pilots remain deferred. They do not become P0 as a result of this truth pass.
