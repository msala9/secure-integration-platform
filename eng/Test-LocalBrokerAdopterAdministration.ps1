# Windows PowerShell 5.1. Runs the BROKER-ADOPT real-service gate with task-owned resources.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PackageDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ExpectedManifestSha256,
    [Parameter(Mandatory = $true)][string] $EvidenceDirectory,
    [ValidatePattern('^[a-zA-Z0-9-]{1,40}$')][string] $Instance = ('adopter-' + (Get-Date -Format 'MMddHHmm')),
    [string] $AccountName = ('BrokerAdopt' + (Get-Date -Format 'MMddHH'))
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'ADOPTER_GATE_ADMIN_REQUIRED'
    }
}
function New-EphemeralPassword {
    $bytes = [byte[]]::new(18)
    $rng = [Security.Cryptography.RNGCryptoServiceProvider]::new()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return ('A1!' + [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', 'a').Replace('/', 'b'))
}
function Quote-Arg([string] $Value) {
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}
function Invoke-ChildProcess {
    param(
        [Parameter(Mandatory = $true)][string] $Exe,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $UserName,
        [Parameter(Mandatory = $true)][Security.SecureString] $Password,
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [int] $ExpectedExitCode = 0
    )
    $stdout = Join-Path $WorkingDirectory ('child-' + [guid]::NewGuid().ToString('N') + '.out')
    $stderr = Join-Path $WorkingDirectory ('child-' + [guid]::NewGuid().ToString('N') + '.err')
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Exe
    $info.Arguments = (($Arguments | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $info.UserName = $UserName
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $Password
    $info.LoadUserProfile = $true
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $false
    $info.RedirectStandardError = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $WorkingDirectory
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) {
        try { $process.Kill() } catch { }
        throw 'ADOPTER_GATE_CHILD_TIMEOUT'
    }
    $outTask.Wait()
    $errTask.Wait()
    [IO.File]::WriteAllText($stdout, $outTask.Result, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($stderr, $errTask.Result, [Text.UTF8Encoding]::new($false))
    if ($process.ExitCode -ne $ExpectedExitCode) {
        throw ('ADOPTER_GATE_CHILD_FAILED exit=' + $process.ExitCode + ' stdout=' + (Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash + ' stderr=' + (Get-FileHash -LiteralPath $stderr -Algorithm SHA256).Hash)
    }
    return [ordered]@{
        exe = [IO.Path]::GetFileName($Exe)
        exitCode = $process.ExitCode
        stdoutSha256 = (Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash
        stderrSha256 = (Get-FileHash -LiteralPath $stderr -Algorithm SHA256).Hash
        stdoutBytes = (Get-Item -LiteralPath $stdout).Length
        stderrBytes = (Get-Item -LiteralPath $stderr).Length
    }
}
function Invoke-AdminProcess {
    param([Parameter(Mandatory = $true)][string] $Exe, [Parameter(Mandatory = $true)][string[]] $Arguments, [int] $ExpectedExitCode = 0)
    & $Exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne $ExpectedExitCode) { throw ('ADOPTER_GATE_ADMIN_PROCESS_FAILED exit=' + $LASTEXITCODE) }
    return [ordered]@{ exe = [IO.Path]::GetFileName($Exe); exitCode = $LASTEXITCODE; elevatedCallerDenied = $true }
}
function Read-Json([string] $Path) {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

Assert-Admin
if ($AccountName.Length -gt 20 -or $AccountName -notmatch '^BrokerAdopt[0-9]{6,}$') { throw 'ADOPTER_GATE_ACCOUNT_NAME_INVALID' }
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $evidence) {
    if (-not (Test-Path -LiteralPath $evidence -PathType Container)) { throw 'ADOPTER_GATE_EVIDENCE_PATH_INVALID' }
    if (Test-Path -LiteralPath (Join-Path $evidence 'result.json') -PathType Leaf) { throw 'ADOPTER_GATE_EVIDENCE_RESULT_EXISTS' }
    if (@(Get-ChildItem -LiteralPath $evidence -Force).Count -ne 0) { throw 'ADOPTER_GATE_EVIDENCE_NOT_EMPTY' }
}
else {
    New-Item -ItemType Directory -Path $evidence | Out-Null
}
& (Join-Path $PSScriptRoot 'Test-LocalBrokerPackage.ps1') -PackageDirectory $package -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null

$lifecycle = Join-Path $package 'Invoke-LocalBroker.ps1'
$name = 'SecureIntegrationBroker.Local.' + $Instance
$root = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
$marker = Join-Path $root 'installation.json'
$settingsPath = Join-Path $root 'broker\appsettings.json'
if ((Get-CimInstance Win32_Service -Filter "Name='$name'") -or (Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data)) {
    throw 'ADOPTER_GATE_FRESH_INSTANCE_REQUIRED'
}

$passwordPlain = New-EphemeralPassword
$password = ConvertTo-SecureString $passwordPlain -AsPlainText -Force
$account = $null
$createdAccount = $false
$envelope = Join-Path $evidence 'adopter.envelope'
$ledger = [ordered]@{
    sourceCommit = $ExpectedSourceCommit
    manifestSha256 = $ExpectedManifestSha256.ToUpperInvariant()
    instance = $Instance
    service = $name
    phases = @()
}
try {
    $accountDescription = ('Task-owned Broker adopter gate ' + $Instance)
    if ($accountDescription.Length -gt 48) { throw 'ADOPTER_GATE_ACCOUNT_DESCRIPTION_INVALID' }
    New-LocalUser -Name $AccountName -Password $password -Description $accountDescription -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    $createdAccount = $true
    $account = Get-LocalUser -Name $AccountName
    $sid = $account.SID.Value
    $passwordPlain = $null

    & $lifecycle -Command Install -Instance $Instance -BrokerPublishDirectory (Join-Path $package 'broker') -SamplePublishDirectory (Join-Path $package 'sample') -AdopterPublishDirectory (Join-Path $package 'adopter') -ApplicationUserSid $sid -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
    & $lifecycle -Command Start -Instance $Instance | Out-Null
    & $lifecycle -Command Stop -Instance $Instance | Out-Null
    $adopter = Join-Path $root 'adopter\SecureIntegration.Samples.LocalBrokerAdopter.exe'
    $adopterV2Root = Join-Path $root 'adopter-v2'
    Copy-Item -LiteralPath (Join-Path $root 'adopter') -Destination $adopterV2Root -Recurse
    $adopterV2 = Join-Path $adopterV2Root 'SecureIntegration.Samples.LocalBrokerAdopter.exe'
    [IO.File]::Open($adopterV2, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    [IO.File]::AppendAllText($adopterV2, 'BROKER-ADOPT-SYNTHETIC-V2', [Text.Encoding]::ASCII)

    & $lifecycle -Command RegisterApplication -Instance $Instance -ApplicationRegistrationId adopter-eval -ApplicationUserSid $sid -ApplicationExecutablePath $adopter -ApplicationOperations ProtectData,UnprotectData,GetBrokerStatus -ApplicationDataContext adopter-secret:text/plain | Out-Null
    & $lifecycle -Command InspectApplications -Instance $Instance | Out-File -LiteralPath (Join-Path $evidence 'inspect-registered.json') -Encoding utf8
    & $lifecycle -Command Start -Instance $Instance | Out-Null

    $ledger.phases += Invoke-ChildProcess -Exe $adopter -Arguments @('status', $name, $name, 'adopter-eval', '-') -UserName $AccountName -Password $password -WorkingDirectory $evidence
    $ledger.phases += Invoke-ChildProcess -Exe $adopter -Arguments @('protect', $name, $name, 'adopter-eval', $envelope) -UserName $AccountName -Password $password -WorkingDirectory $evidence
    $ledger.phases += Invoke-ChildProcess -Exe $adopter -Arguments @('verify', $name, $name, 'adopter-eval', $envelope) -UserName $AccountName -Password $password -WorkingDirectory $evidence

    & $lifecycle -Command Stop -Instance $Instance | Out-Null
    & $lifecycle -Command Start -Instance $Instance | Out-Null
    $ledger.phases += Invoke-ChildProcess -Exe $adopter -Arguments @('verify', $name, $name, 'adopter-eval', $envelope) -UserName $AccountName -Password $password -WorkingDirectory $evidence

    & $lifecycle -Command Stop -Instance $Instance | Out-Null
    $beforeInvalid = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
    $dotnetHost = Join-Path $root 'adopter-v2\dotnet.exe'
    Copy-Item -LiteralPath $adopterV2 -Destination $dotnetHost
    $invalidDenied = $false
    try { & $lifecycle -Command UpdateApplication -Instance $Instance -ApplicationRegistrationId adopter-eval -ApplicationExecutablePath $dotnetHost | Out-Null }
    catch { if ($_.Exception.Message -like 'LOCAL_BROKER_APPLICATION_GENERIC_HOST_DENIED*') { $invalidDenied = $true } else { throw } }
    if (-not $invalidDenied -or (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -cne $beforeInvalid) { throw 'ADOPTER_GATE_INVALID_UPDATE_NOT_PRESERVED' }

    & $lifecycle -Command UpdateApplication -Instance $Instance -ApplicationRegistrationId adopter-eval -ApplicationExecutablePath $adopterV2 | Out-Null
    & $lifecycle -Command InspectApplications -Instance $Instance | Out-File -LiteralPath (Join-Path $evidence 'inspect-updated.json') -Encoding utf8
    & $lifecycle -Command Start -Instance $Instance | Out-Null
    $ledger.phases += Invoke-ChildProcess -Exe $adopterV2 -Arguments @('verify', $name, $name, 'adopter-eval', $envelope) -UserName $AccountName -Password $password -WorkingDirectory $evidence
    $ledger.phases += Invoke-ChildProcess -Exe $adopter -Arguments @('denied', $name, $name, 'adopter-eval', '-') -UserName $AccountName -Password $password -WorkingDirectory $evidence
    $ledger.phases += Invoke-AdminProcess -Exe $adopterV2 -Arguments @('denied', $name, $name, 'adopter-eval', '-')

    & $lifecycle -Command Stop -Instance $Instance | Out-Null
    & $lifecycle -Command RevokeApplication -Instance $Instance -ApplicationRegistrationId adopter-eval | Out-Null
    & $lifecycle -Command InspectApplications -Instance $Instance | Out-File -LiteralPath (Join-Path $evidence 'inspect-revoked.json') -Encoding utf8
    & $lifecycle -Command Start -Instance $Instance | Out-Null
    $ledger.phases += Invoke-ChildProcess -Exe $adopterV2 -Arguments @('denied', $name, $name, 'adopter-eval', '-') -UserName $AccountName -Password $password -WorkingDirectory $evidence

    $registered = Read-Json (Join-Path $evidence 'inspect-registered.json')
    $updated = Read-Json (Join-Path $evidence 'inspect-updated.json')
    $revoked = Read-Json (Join-Path $evidence 'inspect-revoked.json')
    if (@($registered).Count -ne 2 -or @($updated).Count -ne 2 -or @($revoked).Count -ne 2) { throw 'ADOPTER_GATE_REGISTRATION_COUNT_INVALID' }
    if (($updated | Where-Object { $_.RegistrationId -ceq 'local-sample' }).ExecutablePaths[0] -notlike '*\sample\SecureIntegration.Samples.LocalBroker.exe') { throw 'ADOPTER_GATE_SAMPLE_REGISTRATION_CHANGED' }
    $revokedApp = @($revoked | Where-Object { $_.RegistrationId -ceq 'adopter-eval' })[0]
    if (-not $revokedApp.Revoked -or @($revokedApp.AllowedUserSids).Count -ne 0 -or @($revokedApp.AllowedOperations).Count -ne 0) { throw 'ADOPTER_GATE_REVOKE_INVALID' }
    $ledger.accountSid = $sid
    $ledger.result = 'PASS'
    [IO.File]::WriteAllText((Join-Path $evidence 'result.json'), ($ledger | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath $envelope -Force
    & $lifecycle -Command Stop -Instance $Instance | Out-Null
    Disable-LocalUser -Name $AccountName
    Write-Output ('BROKER_ADOPT_REAL_SERVICE=PASS EVIDENCE=' + (Join-Path $evidence 'result.json'))
}
finally {
    if ($password) { $password.Dispose() }
    if ($createdAccount) {
        try { Disable-LocalUser -Name $AccountName } catch { }
    }
    if ($passwordPlain) { $passwordPlain = $null }
}
