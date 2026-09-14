# M5 Admin UI local quick start

Prerequisites: Docker Desktop/Linux Engine with Compose, .NET SDK from `global.json`, Node 22 and PowerShell 7 or Windows PowerShell 5.1.

```powershell
git clone https://github.com/marcobiz/secure-integration-platform.git
cd secure-integration-platform
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Validate
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Workflow
```

Open `https://localhost:18443/admin/` after completing the host trust procedure below. DevelopmentAuth offers fixed synthetic identities: viewer, editor, approver, operator and security-admin. It is disabled by default outside this Compose overlay and Production refuses to start with it enabled.

## Windows host browser trust

Chrome or Edge can use the Windows current-user root store. The quickstart does not
install its synthetic CA. Do not bypass a certificate warning or disable TLS checks.
For a manually inspected `Start` run, the machine owner must explicitly approve
trusting that run's exact public CA. This trust applies to applications of that
Windows user, not just localhost, and persists until removed. No machine-wide root
or browser policy change is required.

From the directory where you started the quickstart, inspect only its public CA:

```powershell
$caPath = (Resolve-Path .\.artifacts\m5\quickstart\raw\certificates\ca.crt).Path
$previewCa = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
$sha256 = [Security.Cryptography.SHA256]::Create()
$caHash = [BitConverter]::ToString($sha256.ComputeHash($previewCa.RawData)).Replace('-', '')
$sha256.Dispose()
$publicFixture = Get-Content .\.artifacts\m5\quickstart\raw\fixture-public.json -Raw | ConvertFrom-Json
if ($caHash -ne $publicFixture.caSha256 -or $previewCa.HasPrivateKey -or
    $previewCa.NotBefore -gt (Get-Date) -or $previewCa.NotAfter -lt (Get-Date)) {
    throw 'PREVIEW_CA_VALIDATION_FAILED'
}
$previewCa | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint
$caHash
$rootPath = 'Cert:\CurrentUser\Root\' + $previewCa.Thumbprint
if (Test-Path -LiteralPath $rootPath) { throw 'PREVIEW_CA_ALREADY_TRUSTED_REVIEW_OWNERSHIP' }
```

Record the SHA-256, expiry and exact removal path in the private candidate record.
The fixture comparison checks consistency with your own run, not publisher identity.
After the owner approves this exact certificate and scope, import it:

```powershell
certutil.exe -user -addstore Root $caPath
if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $rootPath)) {
    throw 'PREVIEW_CA_IMPORT_FAILED'
}
```

Confirm the matching subject in any Windows confirmation dialog. Open a fresh
Chrome/Edge private window at the URL above. Cancel any optional client-certificate
picker: Admin uses its UI login, not an Installation certificate. Require no TLS
warning and no insecure-connection indicator before signing in. If a warning remains,
stop and inspect the browser's public certificate details; do not proceed through it.

After browser verification, close the evaluation window and remove only the root
you imported, using the recorded path (also works in a new PowerShell session):

```powershell
$rootPath = Read-Host 'Exact Cert:\CurrentUser\Root\thumbprint path recorded for this run'
Remove-Item -LiteralPath $rootPath -ErrorAction Stop
if (Test-Path -LiteralPath $rootPath) { throw 'PREVIEW_CA_CLEANUP_FAILED' }
```

Remove this trust before the quickstart `Stop` deletes the per-run files. Every fresh
run generates a different CA; never import all certificates or keep old preview roots.

## Workflow and cleanup

The M5 overlay publishes HTTPS on host loopback and explicitly authorizes its Docker
bridge host peer (`172.29.44.1`) for DevelopmentAuth. This exact peer setting is accepted
only in `M5Testing`, cannot be combined with forwarded proxies, and never trusts browser
headers. Other container peers remain denied. Do not expose this preview on a LAN.

`Workflow` starts the production-build stack and then runs the deterministic browser/runtime gate. It imports a dedicated `2.0.0` Draft, validates it, creates its complete binding revision, requests approval, proves self-approval is denied, approves as a distinct principal, publishes, grants the already enrolled synthetic installation, invokes that exact published version through authenticated mTLS/PoP runtime, verifies the sanitized vendor response and correlated audit, retires the version, and proves a subsequent invocation is denied. The pre-provisioned `1.0.0` sample therefore cannot short-circuit the documented workflow.

`Start` remains available only when an operator wants to inspect the UI manually. It creates a synthetic Installation and consumes its one-time activation code through the real enrollment challenge and ECDSA proof-of-possession client. Raw activation material remains only under the ignored `.artifacts` tree and is never printed.

For manual inspection, follow [Guided onboarding](../user/guided-connector-onboarding.md)
with the existing Active synthetic Installation and a new version of the sample
definition: Editor imports/validates, Security Administrator configures bindings and
grants, Editor requests approval, and a distinct Approver reviews and publishes.
Reload between phases to check resume. The pre-published `1.0.0` sample alone does
not exercise these role handoffs. Finish by inspecting Audit and Health; an Admin
ready banner alone is not evidence of a Runtime API invocation.

The `Start` inspection path enrolls the Broker in **M3 Security Driver Tenant**,
application **M3 Security Driver**, environment **M3 Security Tests**. Select that
Active Installation for the manual role workflow. The sample endpoint catalog is
available in both M3 environments, scoped to `sample-secure-service` / `submit`;
the security environment's credential and certificate remain separate catalog
records. A primary-environment Pending Installation still requires enrollment.

The browser never receives provider secret values, private keys or arbitrary runtime URLs. PostgreSQL, synthetic provider and mock HTTPS/mTLS service stay on the private Compose network; only Gateway HTTPS is intended for the browser.

Cleanup:

```powershell
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop
```

Verify no container or volume remains for Compose project `secure-integration-m5-quickstart`. Raw fixture files under `.artifacts` are ignored and must not be published.
`Stop` also removes the marker-owned per-run quickstart directory, including activation
material, synthetic private keys and PFX files. It refuses to recursively remove an
unmarked artifact directory.
