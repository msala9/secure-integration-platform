# Local Broker — Windows x64 evaluation package

Extract the complete archive into a new directory. `package-manifest.json` records
the source commit, version and SHA-256 inventory; the adjacent `.zip.sha256` checks
download integrity. These checksums are **not signatures or publisher authentication**.
Obtain the archive, expected source commit, archive checksum and manifest checksum
through a trusted operator-controlled channel. Do not trust values found only inside
the archive as release authenticity.

The package includes .NET 10: no Git, .NET SDK/runtime installation, Node, Docker,
Gateway, database or cloud account is required for local protection. Use Windows
PowerShell 5.1. The selected qualification host is Windows 10 Pro 22H2 x64,
19045.6466; qualification results are reported separately. This is an unsigned
alpha evaluation build, not production support for Windows or an MSI installer.

## Once: user identity, then administrator setup

In the ordinary application user's console, obtain the SID (not a password):

```powershell
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

Give that SID to the administrator. From the extracted package in an **elevated**
Windows PowerShell, set `$applicationSid` to that observed SID, then run:

```powershell
$expectedSource = Read-Host 'Expected source commit from your approved build record'
$expectedManifest = Read-Host 'Expected manifest SHA-256 from your trusted channel'
.\Invoke-LocalBroker.ps1 -Command Install -Instance sample -ApplicationUserSid $applicationSid -ExpectedSourceCommit $expectedSource -ExpectedManifestSha256 $expectedManifest
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

`Install`, `Update` and the service qualification command `Verify` require the
expected source commit and manifest SHA-256.

Those expected values must come from the trusted channel you use to approve the
update, not from the package being installed.

Do not substitute the setup administrator's SID unless that is actually the
application account. Setup grants only that exact account and the installed sample
path/hash, with status and the exact `sample` / `text/plain` and
`installation-credential` / `text/plain` protection contexts. The service runs as
`NT SERVICE\SecureIntegrationBroker.Local.sample`, not as that account. Start reports
SCM running; the authorized user's next command tests actual application readiness.

## Everyday use: no elevation

In an ordinary console under the registered application account:

```powershell
$sample = "$env:ProgramFiles\SecureIntegration\LocalBroker\sample\sample\SecureIntegration.Samples.LocalBroker.exe"
& $sample status SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample -
& $sample protect SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
& $sample verify SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
```

The sample protects synthetic text and refuses to overwrite an envelope. Verify
decrypts in memory and also checks context/tampering denials. It never prints keys,
plaintext or ciphertext. Keep the envelope for the restart/update checks.
The SDK authenticates SCM/PID/pipe ownership before sending application data.
An unavailable or unauthorized service gives a bounded error, not an automatic retry.

## Register your own .NET application

The package also includes a small evaluation app distinct from the bundled sample:

```powershell
$adopter = "$env:ProgramFiles\SecureIntegration\LocalBroker\sample\adopter\SecureIntegration.Samples.LocalBrokerAdopter.exe"
```

Register it explicitly from an elevated Windows PowerShell while the service is
stopped. Use the ordinary application user's SID obtained above:

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command RegisterApplication -Instance sample `
  -ApplicationRegistrationId adopter-eval `
  -ApplicationUserSid $applicationSid `
  -ApplicationExecutablePath $adopter `
  -ApplicationOperations ProtectData,UnprotectData,GetBrokerStatus `
  -ApplicationDataContext adopter-secret:text/plain
.\Invoke-LocalBroker.ps1 -Command InspectApplications -Instance sample
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Then run the app as the ordinary application account:

```powershell
& $adopter status SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample adopter-eval -
& $adopter protect SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample adopter-eval .\adopter.envelope
& $adopter verify SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample adopter-eval .\adopter.envelope
```

The registration grants only the exact SID, installed executable path, SHA-256 and
`adopter-secret` / `text/plain` context. The tool rejects common interpreter or shell
hosts such as `dotnet.exe`, `powershell.exe` and `cmd.exe`; register the installed
application executable, not a general-purpose launcher.

To authorize a replacement executable, stop the service and update only that
registration. Existing Installation state, data keys and ciphertext remain intact:

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command UpdateApplication -Instance sample `
  -ApplicationRegistrationId adopter-eval `
  -ApplicationExecutablePath $adopter
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
& $adopter verify SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample adopter-eval .\adopter.envelope
```

This is an application executable update, not a Broker package update. It does not
copy Broker binaries, rotate keys, change the Installation or overwrite other
registrations.

To revoke the application locally, stop the service and revoke the registration:

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command RevokeApplication -Instance sample -ApplicationRegistrationId adopter-eval
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
& $adopter denied SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample adopter-eval -
```

Revocation leaves the registration metadata, protected data, keys and unrelated
registrations in place. It denies later use by clearing the registered SID,
operations, contexts and Gateway grants; it does not delete envelopes or revoke a
credential at its issuer.

## Replace a hardcoded application credential

This path is for a credential **owned by your application, specific to this
Installation**. Obtain it from the system/account administrator that issues the
credential. Do not copy a vendor-wide credential into the sample. The Broker
protects it at rest; the authorized application receives plaintext in memory.
There is no new secret-retrieval API and the Broker's protection key never leaves
the service.

After the one-time setup above, run under the registered ordinary account:

```powershell
$envelope = Join-Path $env:LOCALAPPDATA 'SecureIntegrationCredentialSample\credential.envelope'
& $sample set-credential SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample $envelope
& $sample use-credential SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample $envelope
```

Enter the initial value at the hidden prompt; Enter finishes, Backspace edits and
Escape cancels. Never put it in command arguments, environment variables, shell
history, source code, configuration, logs or a temporary plaintext file. Automation
can write one UTF-8 line to the process's redirected standard input entirely in
memory; it must not use a plaintext input file. Input is bounded to 1,024 characters.

`CREDENTIAL_SAVED` means the app persisted only the Broker's binary envelope.
`use-credential` is a **new application process**: it reads that file, authenticates
the Broker with the SDK, calls `UnprotectData` and sets a transient .NET client's
`NetworkCredential`. It prints `CREDENTIAL_LOADED_FOR_APPLICATION`, not the value.
No HTTP request is sent and no external authentication is claimed. The existing
`protect`/`verify` commands remain the synthetic lifecycle demonstration.

Run `set-credential` again to replace the value: no compilation, reinstall or key
rotation. The sample verifies the old envelope's scope, stages ciphertext beside
it, flushes, then replaces the file without truncating the previous configuration.
A failure before the replacement commits preserves the old configuration. Inspect
the bounded error and fix the cause before an explicit retry; the sample does not
change the password on the external server and cannot roll back that server.
Concurrent successful saves have last-writer semantics; coordinate credential
changes in your application's existing configuration flow.

The sample creates only the final new application directory under an existing
parent, with an explicit user/SYSTEM/Administrators ACL. Existing directory and file
ownership must match the current user and must not allow other accounts. It never
hardens an arbitrary existing directory, overwrites foreign/corrupt envelopes, or
follows reparse/UNC/alternate-stream paths. Choose a new private local directory,
not a shared folder. There is no automatic plaintext migration, deletion or cleanup
of other files.

### Integration into your .NET application

Reference `SecureIntegration.Broker.Sdk`. Pin the service/pipe and application
registration in trusted configuration. The administrator must register **your
installed executable**, account SID, allowed operations and exact context in the
protected Broker policy; do not grant `dotnet.exe` or a shell. The bundled lifecycle
registers only this sample. Updating an existing installation preserves its policy:
an administrator must explicitly grant the new context before adopting this path.

The application delta is two SDK calls and local ciphertext storage:

```csharp
// Setup/change: utf8Input comes from your protected runtime input, never a constant.
var protectedValue = await broker.ProtectDataAsync(new ProtectDataRequest {
    Purpose = "installation-credential", ContentType = "text/plain",
    PlaintextBase64 = Convert.ToBase64String(utf8Input)
}, cancellationToken);
// Persist only decoded protectedValue.EnvelopeBase64, using the sample's safe save.

// Ordinary startup: read the saved binary envelope, not the old plaintext setting.
var result = await broker.UnprotectDataAsync(new UnprotectDataRequest {
    Purpose = "installation-credential", ContentType = "text/plain",
    EnvelopeBase64 = Convert.ToBase64String(envelopeBytes)
}, cancellationToken);
byte[] plaintext = Convert.FromBase64String(result.PlaintextBase64);
try {
    // THIS replaces the old password constant/configuration read at your client.
    existingClientOptions.Credentials = new NetworkCredential(
        configuredUserName, Encoding.UTF8.GetString(plaintext));
    // Use and dispose your existing client here; never log its credential/options.
}
finally { CryptographicOperations.ZeroMemory(plaintext); }
```

The executable implementation is `samples/LocalBroker/Program.cs` and
`CredentialExample.cs` in the source distribution. Clear owned input/plaintext
buffers in `finally`; the SDK's Base64 contract and .NET credential APIs also use
managed strings, so this is **not a promise of complete memory erasure**. Dispose
your client promptly. Injected code in an authorized app and Administrator/SYSTEM
remain residual threats; this is not a secretless client or a closed management-app
security finding without integrating that actual application.

Errors are bounded: `application_not_authorized`/`data_context_not_granted` require
the administrator to check the registered identity/context; `authentication_failed`
means a tampered or wrong-scope envelope; `CREDENTIAL_OWNERSHIP_DENIED` and
`CREDENTIAL_PATH_DENIED` preserve the file; `LOCAL_BROKER_SAMPLE_FAILED` covers local
I/O or service availability and never includes paths or input. Do not repair these
by reinitializing the Broker's keys or deleting the old configuration.

After migrating a real application, remove plaintext constants/settings from its
build/deployment and revoke any previously hardcoded credential at its issuer.
Removing code does not revoke copies from old binaries/history. If the machine or
service DPAPI profile is lost, the issuer must revoke/reissue the application
credential and the operator must provision a new envelope; copying a DPAPI blob to
another machine is not recovery. Backup/recovery responsibilities remain explicit
with the application operator and credential issuer, not a new Broker recovery service.

## Administrator lifecycle and update

From the extracted package, elevated:

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Stop can be repeated and supports partial setup with verified ownership. It preserves
service registration, binaries, policy, identity and protected state. Foreign or
uncertain resources and reparse paths are denied, not deleted.

To update, obtain a new build, verify its inventory and extract into a **new** directory.
Run this from that new package, elevated:

```powershell
.\Invoke-LocalBroker.ps1 -Command Update -Instance sample -ExpectedSourceCommit $expectedSource -ExpectedManifestSha256 $expectedManifest
```

Then run `verify` as the ordinary application user against the original envelope.
Update preserves policy/identity/keys and updates the authorized sample hash; key
initialization is disabled before copying. Manifest, source-commit or inventory
mismatches are rejected before the service is stopped or files are copied. A failed update reports failure and
preserves state: fix the cause and explicitly repeat Update, never Install or key
initialization as recovery. This is not transactional rollback or a general guarantee
of compatibility across releases; compare the declared source commits, not just
the shared alpha version. The current package remains UNSIGNED_ARTIFACTS:
PUBLISHER_AUTHENTICITY_NOT_QUALIFIED is an explicit limit until a later authorized
signing design exists.

Back up installation metadata, policy, the complete protected data directory and
ciphertext while stopped, retaining ACLs and the Windows/service profile required
by DPAPI. Blobs alone are not portable recovery material. Machine/profile loss can
make data unrecoverable. Administrator/SYSTEM and code injected into an authorized
application remain residual threats. There is no destructive uninstall in this guide.
