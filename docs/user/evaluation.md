# Evaluate SIP

**Status:** evaluation candidate preparation; no release or publication approval.
Use the exact source commit and artifact hashes supplied in the candidate record.
The existing product version is `0.1.0-alpha.1`; it does not identify a unique build.

| Path | Receive | Demonstrates | Prerequisites |
|---|---|---|---|
| A. Core | Core source export, inventory and SHA-256 sidecars | Direct .NET → Gateway → Published Connector → synthetic HTTPS/mTLS service | PowerShell 5.1 or 7, Linux Docker Engine/Desktop with Compose; network for uncached pinned images/packages |
| B. Windows | Complete `local-broker-0.1.0-alpha.1-win-x64-<commit>.zip`, archive and manifest hashes | Registered application → local Windows Service, with Gateway disabled | Windows 10 Pro 22H2 x64 build 19045.6466, PowerShell 5.1, administrator for setup and a separate ordinary application account |

Both paths use synthetic data. Neither requires Azure, FSE2 or customer material.
Windows is a selected qualification target, not a compatibility or support-period promise.
Git is needed to obtain a repository checkout; an extracted Core export needs no Git
to run the pilot. Neither runtime path needs a host .NET SDK, Node or PostgreSQL.

## Check the delivery

Obtain the approved source commit, archive SHA-256 and manifest SHA-256 through your
trusted delivery channel. Compare the archive before extracting into a new directory:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\received-package.zip
```

For Core, the manifest is `OPEN_SOURCE_EXPORT_MANIFEST.json`; its inventory includes
file paths, lengths and hashes. From the extracted Core root, verify the inventory
against the approved commit:

```powershell
$approvedSource = Read-Host 'Approved source commit from delivery record'
.\eng\Test-OpenSourceCoreInventory.ps1 -ExportDirectory (Get-Location).Path -ExpectedSourceCommit $approvedSource
```

For Windows, `package-manifest.json` records `sourceCommit`, `win-x64`, included
runtime dependency manifests and the closed file inventory. Install/Update also
require the externally approved manifest hash. A checksum proves integrity against
an expected value, not publisher authenticity. DCO sign-off is not a binary signature.
These are unsigned alpha artifacts. Keep the included licenses and notices.

## A. Run the Core

Use a free Docker environment: no existing resources for Compose project
`secure-integration-m5-quickstart`, and free loopback ports 18443–18445. If another
evaluation owns those resources, stop here and use a separate Docker environment;
do not run cleanup against another operator's installation.
From the extracted Core root:

```powershell
.\tools\alpha\Invoke-AlphaGoldenPath.ps1 -Phase Validate
.\tools\alpha\Invoke-AlphaGoldenPath.ps1 -Phase Run
```

Expected: `ALPHA_GOLDEN_PATH_PASS`, one accepted synthetic invocation, sanitized
response, metadata-only audit and zero owned resources after automatic cleanup.
Builds run in pinned containers; do not use `-SkipBuild` for first adoption.
See [the local pilot](local-pilot.md) for the individual result markers.

### Open Admin from the host browser

After the pilot has cleaned up, start the existing inspection environment with the
same containerized .NET tooling:

```powershell
$containerDotNet = (Resolve-Path .\tools\alpha\Invoke-AlphaContainerDotNet.ps1).Path
.\tools\m5\Invoke-M5Quickstart.ps1 -Phase Start -DotNetPath $containerDotNet
```

Open `https://localhost:18443/admin/` in a fresh host browser session. The local
synthetic CA is not publicly trusted: accept it only for this isolated loopback
evaluation, following the [Admin quickstart](../operations/M5-ADMIN-QUICKSTART.md).
Sign in through the UI using its synthetic identity selection. Do not pre-login by API.
Follow [Guided onboarding](guided-connector-onboarding.md): Security Administrator,
Editor and distinct Approver perform their authorized actions. Use the existing
Active synthetic Installation to inspect the supported path; creating another
Installation requires its separate one-time enrollment handoff.
Reload to check persisted progress, then log out and sign in again. `Published`
describes Connector configuration; it does not itself prove an invocation.
The automated Core result and this manual Admin inspection are separate checks.

### Stop, restart and recovery

After Admin inspection, or after an interrupted setup:

```powershell
.\tools\alpha\Invoke-AlphaGoldenPath.ps1 -Phase Stop
.\tools\alpha\Invoke-AlphaGoldenPath.ps1 -Phase Stop
.\tools\alpha\Invoke-AlphaGoldenPath.ps1 -Phase Run
```

Repeat Stop only for your own run. Expect zero owned containers, networks, volumes
and synthetic material. A fresh Run starts again; intermediate setup is not resumed.
For an evaluation update, stop the old run, extract the approved new candidate into
a new directory and repeat the path. This resets synthetic evaluation state; it is
not an in-place production data migration or rollback guarantee.

## B. Run the Windows package

Extract the entire Windows archive. Follow its `README.md`, also available as the
[Windows package guide](../../deploy/windows/README.md), in this order:

1. Obtain the ordinary application's user SID; administrator installs the package
   with the approved source/manifest hashes.
2. Register the included distinct `adopter` executable using RegisterApplication,
   exact SID, operations and `adopter-secret:text/plain`; inspect and start.
3. As the ordinary account, run adopter `status`, `protect`, then `verify` in new
   processes. Expected: `PASS GATEWAY=DISABLED`.
4. Administrator stops/starts, then the ordinary account verifies the original
   envelope. Use UpdateApplication for an explicitly approved executable change;
   verify reuse and RevokeApplication denial through the guide.
5. For one application-owned per-Installation credential, use the included sample's
   `set-credential` hidden prompt and `use-credential` in a new ordinary process.
   Enter only disposable synthetic input. Expected: `CREDENTIAL_SAVED` followed by
   `CREDENTIAL_LOADED_FOR_APPLICATION`; no external authentication occurs.

The distinct adopter demonstrates registration and protection with synthetic text;
the included credential sample demonstrates runtime input and ciphertext-only
configuration. Neither is integration into your actual management application.
Administrator setup and ordinary-account invocation are different responsibilities.

Stop can be repeated. Windows Stop preserves installation, policy, keys and protected
data; it is not uninstall. Package Update preserves state and requires a new approved
manifest; it is distinct from UpdateApplication. Follow the package guide for failed
update recovery. Never recover by deleting keys or rerunning initialization.
There is no transactional rollback or arbitrary cross-version compatibility promise.

## Limits and candidate record

Keep artifacts and synthetic operational state separate. Never redistribute generated
activation material, private certificates, `.env`, ciphertext or evidence containing
credentials. Local Administrator/SYSTEM and a compromised authorized application
remain residual threats. DPAPI blobs alone do not recover a lost machine/profile.
The Direct sample's process-local client key is evaluation-only.

The delivery record must identify source commit/tree, artifact and manifest hashes,
target, observed time/steps, Core/Admin/recovery/Windows outcomes, cleanup and open
blockers. Previous source evidence does not qualify a newly built package. Building
Core in an export is separate from building the Windows package: the Windows builder
requires a clean Git worktree and records that repository's source commit.
No stable API, production readiness, certification, publisher signature, customer CVD
remediation or release approval is implied. See [known limitations](known-limitations.md).
