# Windows PowerShell 5.1. Uses published binaries; no SDK is needed on the runtime host.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Start', 'Stop', 'Update', 'Verify', 'RegisterApplication', 'InspectApplications', 'UpdateApplication', 'RevokeApplication')] [string] $Command = 'Start',
    [ValidatePattern('^[a-zA-Z0-9-]{1,40}$')] [string] $Instance = 'sample',
    [string] $BrokerPublishDirectory = (Join-Path $PSScriptRoot 'broker'),
    [string] $SamplePublishDirectory = (Join-Path $PSScriptRoot 'sample'),
    [string] $AdopterPublishDirectory = (Join-Path $PSScriptRoot 'adopter'),
    [ValidatePattern('^[0-9a-f]{40}$')] [string] $ExpectedSourceCommit,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')] [string] $ExpectedManifestSha256,
    [string] $ApplicationUserSid,
    [ValidatePattern('^[a-zA-Z0-9._-]{1,128}$')] [string] $ApplicationRegistrationId,
    [string] $ApplicationExecutablePath,
    [string[]] $ApplicationOperations,
    [string[]] $ApplicationDataContext
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'LOCAL_BROKER_ADMIN_REQUIRED: service lifecycle requires an elevated Windows PowerShell.'
}
$name = 'SecureIntegrationBroker.Local.' + $Instance
$root = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
$brokerDirectory = Join-Path $root 'broker'
$sampleDirectory = Join-Path $root 'sample'
$adopterDirectory = Join-Path $root 'adopter'
$executable = Join-Path $brokerDirectory 'SecureIntegration.Broker.Service.exe'
$sample = Join-Path $sampleDirectory 'SecureIntegration.Samples.LocalBroker.exe'
$adopter = Join-Path $adopterDirectory 'SecureIntegration.Samples.LocalBrokerAdopter.exe'
$binaryPath = '"' + $executable + '" --contentRoot "' + $brokerDirectory + '"'
$marker = Join-Path $root 'installation.json'
$settingsPath = Join-Path $brokerDirectory 'appsettings.json'

function Assert-NoReparse([string] $Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'LOCAL_BROKER_REPARSE_PATH_DENIED'
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}
function Get-OwnedService {
    Assert-NoReparse $root
    Assert-NoReparse $data
    $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (-not (Test-Path -LiteralPath $marker)) {
        if ($service -or (Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data)) { throw 'LOCAL_BROKER_OWNERSHIP_UNCERTAIN: existing resources preserved.' }
        return $null
    }
    Assert-NoReparse $marker
    $record = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($record.service -cne $name -or $record.root -cne $root -or $record.data -cne $data -or $record.binaryPath -cne $binaryPath) {
        throw 'LOCAL_BROKER_OWNERSHIP_UNCERTAIN: installation marker does not match.'
    }
    if ($service -and ($service.PathName -cne $binaryPath -or $service.StartName -ine ('NT SERVICE\' + $name))) {
        throw 'LOCAL_BROKER_FOREIGN_SERVICE: service preserved.'
    }
    return $service
}
function Invoke-ServiceAction([string] $Action) {
    if ($Action -eq 'Create') {
        # CIM preserves the exact quoted image path under Windows PowerShell 5.1 as well as PowerShell 7.
        $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
            Name = $name; DisplayName = $name; PathName = $binaryPath; ServiceType = [byte]16;
            ErrorControl = [byte]1; StartMode = 'Manual'; DesktopInteract = $false; StartName = 'NT SERVICE\' + $name
        }
    }
    else {
        $target = Get-OwnedService
        if (-not $target) { throw 'LOCAL_BROKER_SERVICE_ABSENT' }
        $method = switch ($Action) { 'Start' { 'StartService' }; 'Stop' { 'StopService' }; 'Delete' { 'Delete' }; default { throw 'LOCAL_BROKER_INVALID_ACTION' } }
        $result = Invoke-CimMethod -InputObject $target -MethodName $method
    }
    if ($result.ReturnValue -ne 0) { throw ('LOCAL_BROKER_SERVICE_ACTION_FAILED: ' + $Action + ' result ' + $result.ReturnValue) }
}
function Set-DirectoryRights([string] $Path, [string] $ServiceSid, [bool] $PublicRead) {
    Assert-NoReparse $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $ServiceSid)) {
        $rights = if ($PublicRead -and $sid -eq $ServiceSid -and $sid -like 'S-1-5-80-*') { 'ReadAndExecute' } else { 'FullControl' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($PublicRead) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Copy-Published([string] $Source, [string] $Destination) {
    if (-not $Source -or -not (Test-Path -LiteralPath $Source -PathType Container)) { throw 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED' }
    Assert-NoReparse $Source
    Assert-NoReparse $Destination
    $sourceRoot = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\')
    foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'LOCAL_BROKER_REPARSE_PATH_DENIED' }
        $relative = $file.FullName.Substring($sourceRoot.Length + 1)
        $target = Join-Path $Destination $relative
        Assert-NoReparse $target
        if ($file.PSIsContainer) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
        elseif ($file.Name -notlike 'appsettings*.json') { Copy-Item -LiteralPath $file.FullName -Destination $target -Force }
    }
}
function Assert-ExpectedPackage {
    if ([string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -or [string]::IsNullOrWhiteSpace($ExpectedManifestSha256)) {
        throw 'LOCAL_BROKER_EXPECTED_PACKAGE_REQUIRED: confirm ExpectedSourceCommit and ExpectedManifestSha256 through the operator trusted channel.'
    }
    if ([string]::IsNullOrWhiteSpace($BrokerPublishDirectory) -or [string]::IsNullOrWhiteSpace($SamplePublishDirectory) -or
        -not (Test-Path -LiteralPath $BrokerPublishDirectory -PathType Container) -or
        -not (Test-Path -LiteralPath $SamplePublishDirectory -PathType Container)) {
        throw 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED'
    }
    $brokerSource = (Resolve-Path -LiteralPath $BrokerPublishDirectory).Path.TrimEnd('\')
    $sampleSource = (Resolve-Path -LiteralPath $SamplePublishDirectory).Path.TrimEnd('\')
    $package = Split-Path -Parent $brokerSource
    if ((Split-Path -Parent $sampleSource) -cne $package) { throw 'LOCAL_BROKER_PACKAGE_LAYOUT_INVALID' }
    if (-not [string]::IsNullOrWhiteSpace($AdopterPublishDirectory) -and (Test-Path -LiteralPath $AdopterPublishDirectory -PathType Container)) {
        $adopterSource = (Resolve-Path -LiteralPath $AdopterPublishDirectory).Path.TrimEnd('\')
        if ((Split-Path -Parent $adopterSource) -cne $package) { throw 'LOCAL_BROKER_PACKAGE_LAYOUT_INVALID' }
    }
    $manifestPath = Join-Path $package 'package-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'LOCAL_BROKER_PACKAGE_MANIFEST_REQUIRED' }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne $ExpectedManifestSha256.ToUpperInvariant()) {
        throw 'LOCAL_BROKER_PACKAGE_MANIFEST_HASH_MISMATCH'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or $manifest.sourceCommit -cne $ExpectedSourceCommit -or
        $manifest.product -cne 'SecureIntegration.LocalBroker' -or $manifest.runtimeIdentifier -cne 'win-x64' -or
        -not $manifest.selfContained -or [string]$manifest.integrity -cne 'SHA-256 inventory, not a signature or publisher authentication') {
        throw 'LOCAL_BROKER_PACKAGE_MANIFEST_INVALID'
    }
    $actual = @(Get-ChildItem -LiteralPath $package -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($package.Length + 1).Replace('\', '/') })
    $expected = @($manifest.files.path) + @('package-manifest.json')
    if (@(Compare-Object $actual $expected).Count -ne 0 -or @($expected | Select-Object -Unique).Count -ne $expected.Count) {
        throw 'LOCAL_BROKER_PACKAGE_INVENTORY_MISMATCH'
    }
    foreach ($entry in $manifest.files) {
        if ($entry.path -cnotmatch '^(broker|sample|adopter)/[a-zA-Z0-9_./-]+\.(dll|exe|deps\.json|runtimeconfig\.json|txt)$' -and
            $entry.path -cnotin @('Invoke-LocalBroker.ps1', 'README.md', 'LICENSE', 'LICENSE-APACHE-2.0', 'NOTICE')) { throw 'LOCAL_BROKER_PACKAGE_FILE_DENIED' }
        $path = [IO.Path]::GetFullPath((Join-Path $package $entry.path))
        if (-not $path.StartsWith($package + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'LOCAL_BROKER_PACKAGE_PATH_DENIED' }
        if ((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $entry.sha256) { throw 'LOCAL_BROKER_PACKAGE_HASH_MISMATCH' }
    }
}
function Write-Settings($Value) {
    Assert-NoReparse $settingsPath
    $directory = Split-Path -Parent $settingsPath
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $temporary = Join-Path $directory ('.appsettings-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $backup = Join-Path $directory ('.appsettings-backup-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
            [IO.File]::Replace($temporary, $settingsPath, $backup)
        }
        else {
            [IO.File]::Move($temporary, $settingsPath)
        }
        $temporary = $null
    }
    finally {
        if ($temporary -and (Test-Path -LiteralPath $temporary -PathType Leaf)) { Remove-Item -LiteralPath $temporary -Force }
        if (Test-Path -LiteralPath $backup -PathType Leaf) { Remove-Item -LiteralPath $backup -Force }
    }
}
function Read-Settings {
    if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) { throw 'LOCAL_BROKER_SETTINGS_ABSENT' }
    Assert-NoReparse $settingsPath
    return Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
}
function Assert-ServiceStoppedForApplicationChange {
    param($Service)
    if ($Service -and $Service.State -ne 'Stopped') { throw 'LOCAL_BROKER_APPLICATION_CHANGE_REQUIRES_STOP: stop the owned service before editing application policy.' }
}
function Get-CanonicalApplicationExecutable {
    if ([string]::IsNullOrWhiteSpace($ApplicationExecutablePath)) { throw 'LOCAL_BROKER_APPLICATION_EXECUTABLE_REQUIRED' }
    $path = [IO.Path]::GetFullPath($ApplicationExecutablePath)
    Assert-NoReparse $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'LOCAL_BROKER_APPLICATION_EXECUTABLE_REQUIRED' }
    $leaf = [IO.Path]::GetFileName($path)
    if ($leaf -cin @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'dotnet.exe')) {
        throw 'LOCAL_BROKER_APPLICATION_GENERIC_HOST_DENIED'
    }
    return (Resolve-Path -LiteralPath $path).Path
}
function Get-ApplicationOperations {
    $requested = @($ApplicationOperations)
    if ($requested.Count -eq 0) { $requested = @('ProtectData', 'UnprotectData', 'GetBrokerStatus') }
    $allowed = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
    if (@($requested | Select-Object -Unique).Count -ne $requested.Count) { throw 'LOCAL_BROKER_APPLICATION_OPERATIONS_INVALID' }
    foreach ($operation in $requested) {
        if ($operation -cnotin $allowed) { throw 'LOCAL_BROKER_APPLICATION_OPERATIONS_INVALID' }
    }
    return @($requested)
}
function Get-ApplicationContexts {
    $contexts = @()
    foreach ($entry in @($ApplicationDataContext)) {
        if ([string]::IsNullOrWhiteSpace($entry)) { throw 'LOCAL_BROKER_APPLICATION_CONTEXT_INVALID' }
        $separator = $entry.IndexOf(':')
        if ($separator -le 0 -or $separator -ge ($entry.Length - 1)) { throw 'LOCAL_BROKER_APPLICATION_CONTEXT_INVALID' }
        $purpose = $entry.Substring(0, $separator)
        $contentType = $entry.Substring($separator + 1)
        if ($purpose.Length -gt 128 -or $contentType.Length -gt 128 -or
            $purpose -match '[\r\n]' -or $contentType -match '[\r\n]' -or $contentType -notmatch '^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$') {
            throw 'LOCAL_BROKER_APPLICATION_CONTEXT_INVALID'
        }
        $contexts += [ordered]@{ Purpose = $purpose; ContentType = $contentType }
    }
    if (@($contexts | ForEach-Object { $_.Purpose + ':' + $_.ContentType } | Select-Object -Unique).Count -ne $contexts.Count) {
        throw 'LOCAL_BROKER_APPLICATION_CONTEXT_INVALID'
    }
    return @($contexts)
}
function Get-ApplicationIndex($Settings, [string] $RegistrationId) {
    $matches = @()
    for ($index = 0; $index -lt @($Settings.Broker.Applications).Count; $index++) {
        if ($Settings.Broker.Applications[$index].RegistrationId -ceq $RegistrationId) { $matches += $index }
    }
    if ($matches.Count -gt 1) { throw 'LOCAL_BROKER_APPLICATION_DUPLICATE_REGISTRATION' }
    if ($matches.Count -eq 0) { return -1 }
    return $matches[0]
}
function New-ApplicationPolicy {
    $sid = Get-ApplicationUserSid
    $path = Get-CanonicalApplicationExecutable
    $operations = Get-ApplicationOperations
    $contexts = Get-ApplicationContexts
    return [ordered]@{
        RegistrationId = $ApplicationRegistrationId
        AllowedUserSids = @($sid)
        ExecutablePaths = @($path)
        ExecutableSha256 = @((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
        AllowedPublisherThumbprints = @()
        AllowedOperations = @($operations)
        AllowedDataProtectionContexts = @($contexts)
        GatewayGrants = @()
    }
}
function Get-ApplicationUserSid {
    if ([string]::IsNullOrWhiteSpace($ApplicationUserSid)) {
        throw 'LOCAL_BROKER_APPLICATION_SID_REQUIRED: pass the SID of the application user, not implicitly the setup administrator.'
    }
    try {
        $sid = [Security.Principal.SecurityIdentifier]::new($ApplicationUserSid)
        if (-not $sid.IsAccountSid()) { throw 'Not an account SID.' }
        $null = $sid.Translate([Security.Principal.NTAccount])
        return $sid.Value
    }
    catch { throw 'LOCAL_BROKER_APPLICATION_SID_INVALID: use an existing Windows account SID.' }
}
function Invoke-Sample([string] $Action, [string] $Envelope, [string] $Application = 'local-sample') {
    & $sample $Action $name $name $Application $Envelope
    if ($LASTEXITCODE -ne 0) { throw 'LOCAL_BROKER_SAMPLE_FAILED: inspect the bounded error code.' }
}

if ($Command -eq 'Verify') {
    # Qualification uses the same installer/lifecycle, not a separate service implementation.
    if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data) -or (Get-CimInstance Win32_Service -Filter "Name='$name'")) {
        throw 'LOCAL_BROKER_VERIFY_REQUIRES_FRESH_INSTANCE: choose a new Instance; existing state is preserved.'
    }
    $started = [Diagnostics.Stopwatch]::StartNew()
    $envelope = Join-Path $env:TEMP ($name + '.envelope')
    if (Test-Path -LiteralPath $envelope) { throw 'LOCAL_BROKER_VERIFY_ENVELOPE_COLLISION' }
    try {
        & $PSCommandPath -Command Install -Instance $Instance -BrokerPublishDirectory $BrokerPublishDirectory -SamplePublishDirectory $SamplePublishDirectory -AdopterPublishDirectory $AdopterPublishDirectory -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256 -ApplicationUserSid $identity.User.Value
        & $PSCommandPath -Command Start -Instance $Instance
        Invoke-Sample 'protect' $envelope
        Write-Output ('FIRST_PROTECT_MS=' + $started.ElapsedMilliseconds)
        $stateHashes = @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash)
        $acl = (Get-Acl -LiteralPath $data).Sddl
        $installationHash = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        & $PSCommandPath -Command Stop -Instance $Instance
        & $PSCommandPath -Command Stop -Instance $Instance
        & $PSCommandPath -Command Start -Instance $Instance
        Invoke-Sample 'verify' $envelope
        Invoke-Sample 'denied' $envelope 'unregistered-app'
        # The same registration from the unstaged executable must fail process/path authorization.
        & (Join-Path $SamplePublishDirectory 'SecureIntegration.Samples.LocalBroker.exe') 'denied' $name $name 'local-sample' '-'
        if ($LASTEXITCODE -ne 0) { throw 'LOCAL_BROKER_UNAUTHORIZED_PROCESS_TEST_FAILED' }
        & $PSCommandPath -Command Update -Instance $Instance -BrokerPublishDirectory $BrokerPublishDirectory -SamplePublishDirectory $SamplePublishDirectory -AdopterPublishDirectory $AdopterPublishDirectory -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256
        Invoke-Sample 'verify' $envelope
        $after = @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash)
        if (($stateHashes -join ',') -cne ($after -join ',') -or $acl -cne (Get-Acl -LiteralPath $data).Sddl -or
            $installationHash -cne (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash) { throw 'LOCAL_BROKER_STATE_CHANGED' }
        Write-Output 'REAL_WINDOWS_SERVICE_RESTART_UPDATE=PASS'
    }
    finally {
        # Only remove the exact owned service registration; retain protected state for same-profile recovery.
        $owned = Get-OwnedService
        if ($owned) {
            & $PSCommandPath -Command Stop -Instance $Instance
            $owned = Get-OwnedService
            if ($owned) { Invoke-ServiceAction 'Delete' }
        }
        Write-Output 'CLEANUP=PERSISTENT_STATE_PRESERVED'
    }
    return
}

$owned = Get-OwnedService
if ($Command -eq 'Stop') {
    if ($owned -and $owned.State -ne 'Stopped') {
        Invoke-ServiceAction 'Stop'
        (Get-Service -Name $name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Write-Output 'STOP=COMPLETE DATA=PRESERVED'
    return
}
if ($Command -eq 'Install') {
    Assert-ExpectedPackage
    if (-not (Test-Path -LiteralPath (Join-Path $BrokerPublishDirectory 'SecureIntegration.Broker.Service.exe')) -or
        -not (Test-Path -LiteralPath (Join-Path $SamplePublishDirectory 'SecureIntegration.Samples.LocalBroker.exe'))) { throw 'LOCAL_BROKER_PUBLISHED_APPHOST_REQUIRED' }
    if (Test-Path -LiteralPath $marker) {
        $record = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        if ($owned -and (Test-Path -LiteralPath $settingsPath) -and (Test-Path -LiteralPath $sample) -and (Test-Path -LiteralPath $executable)) {
            Write-Output 'INSTALL=EXISTS NEXT=START_OR_UPDATE'; return
        }
        if ((Test-Path -LiteralPath $data) -and @(Get-ChildItem -LiteralPath $data -Recurse -File).Count -ne 0) {
            throw 'LOCAL_BROKER_PARTIAL_WITH_DATA: preserve and restore the existing installation; initialization is not recovery.'
        }
    }
    else {
        $ApplicationUserSid = Get-ApplicationUserSid
        if ([Diagnostics.EventLog]::SourceExists($name)) { throw 'LOCAL_BROKER_FOREIGN_EVENT_SOURCE: choose a fresh Instance.' }
        # Claim fresh directories before SCM creation, so partial installation is recognizable.
        Set-DirectoryRights $root 'S-1-5-18' $true
        $record = [ordered]@{ service = $name; root = $root; data = $data; binaryPath = $binaryPath; installationId = [guid]::NewGuid().ToString('D') }
        [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    $ApplicationUserSid = Get-ApplicationUserSid
    if (-not $owned) { Invoke-ServiceAction 'Create' }
    $serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE', $name)).Translate([Security.Principal.SecurityIdentifier]).Value
    Set-DirectoryRights $root $serviceSid $true
    Set-DirectoryRights $data $serviceSid $false
    New-Item -ItemType Directory -Path $brokerDirectory, $sampleDirectory -Force | Out-Null
    Copy-Published $BrokerPublishDirectory $brokerDirectory
    Copy-Published $SamplePublishDirectory $sampleDirectory
    if (-not [string]::IsNullOrWhiteSpace($AdopterPublishDirectory) -and (Test-Path -LiteralPath $AdopterPublishDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $adopterDirectory -Force | Out-Null
        Copy-Published $AdopterPublishDirectory $adopterDirectory
    }
    $settings = @{ Broker = @{ ServiceName = $name; PipeName = $name; InstallationId = $record.installationId; DataDirectory = $data; InitializeDataKeys = $true; Gateway = @{ Enabled = $false }; Applications = @(@{
        RegistrationId = 'local-sample'; AllowedUserSids = @($ApplicationUserSid); ExecutablePaths = @($sample); ExecutableSha256 = @((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash); AllowedOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
        AllowedDataProtectionContexts = @(@{ Purpose = 'sample'; ContentType = 'text/plain' },
            @{ Purpose = 'installation-credential'; ContentType = 'text/plain' })
    }) } }
    Write-Settings $settings
    if (-not [Diagnostics.EventLog]::SourceExists($name)) { New-EventLog -LogName Application -Source $name }
    Write-Output 'INSTALL=COMPLETE NEXT=START'
    return
}
if (-not $owned) { throw 'LOCAL_BROKER_SERVICE_ABSENT: install a fresh instance or restore the existing installation; do not reinitialize data.' }
if ($Command -eq 'InspectApplications') {
    $settings = Read-Settings
    $report = @($settings.Broker.Applications | ForEach-Object {
        [ordered]@{
            RegistrationId = $_.RegistrationId
            AllowedUserSids = @($_.AllowedUserSids)
            ExecutablePaths = @($_.ExecutablePaths)
            ExecutableSha256 = @($_.ExecutableSha256)
            AllowedOperations = @($_.AllowedOperations)
            AllowedDataProtectionContexts = @($_.AllowedDataProtectionContexts | ForEach-Object { [ordered]@{ Purpose = $_.Purpose; ContentType = $_.ContentType } })
            Revoked = (@($_.AllowedUserSids).Count -eq 0 -or @($_.AllowedOperations).Count -eq 0)
        }
    })
    $report | ConvertTo-Json -Depth 6
    return
}
if ($Command -eq 'RegisterApplication') {
    Assert-ServiceStoppedForApplicationChange $owned
    if ([string]::IsNullOrWhiteSpace($ApplicationRegistrationId)) { throw 'LOCAL_BROKER_APPLICATION_REGISTRATION_REQUIRED' }
    $settings = Read-Settings
    if ($settings.Broker.Gateway.Enabled) { throw 'LOCAL_BROKER_APPLICATION_GATEWAY_MUST_BE_DISABLED' }
    if ((Get-ApplicationIndex $settings $ApplicationRegistrationId) -ne -1) { throw 'LOCAL_BROKER_APPLICATION_ALREADY_REGISTERED' }
    $settings.Broker.Applications += (New-ApplicationPolicy)
    Write-Settings $settings
    Write-Output ('APPLICATION_REGISTERED=' + $ApplicationRegistrationId + ' NEXT=START')
    return
}
if ($Command -eq 'UpdateApplication') {
    Assert-ServiceStoppedForApplicationChange $owned
    if ([string]::IsNullOrWhiteSpace($ApplicationRegistrationId)) { throw 'LOCAL_BROKER_APPLICATION_REGISTRATION_REQUIRED' }
    $settings = Read-Settings
    $index = Get-ApplicationIndex $settings $ApplicationRegistrationId
    if ($index -lt 0) { throw 'LOCAL_BROKER_APPLICATION_NOT_REGISTERED' }
    $path = Get-CanonicalApplicationExecutable
    $settings.Broker.Applications[$index].ExecutablePaths = @($path)
    $settings.Broker.Applications[$index].ExecutableSha256 = @((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
    if ($settings.Broker.Applications[$index].AllowedUserSids.Count -eq 0) {
        $settings.Broker.Applications[$index].AllowedUserSids = @((Get-ApplicationUserSid))
    }
    Write-Settings $settings
    Write-Output ('APPLICATION_UPDATED=' + $ApplicationRegistrationId + ' NEXT=START')
    return
}
if ($Command -eq 'RevokeApplication') {
    Assert-ServiceStoppedForApplicationChange $owned
    if ([string]::IsNullOrWhiteSpace($ApplicationRegistrationId)) { throw 'LOCAL_BROKER_APPLICATION_REGISTRATION_REQUIRED' }
    $settings = Read-Settings
    $index = Get-ApplicationIndex $settings $ApplicationRegistrationId
    if ($index -lt 0) { throw 'LOCAL_BROKER_APPLICATION_NOT_REGISTERED' }
    $settings.Broker.Applications[$index].AllowedUserSids = @()
    $settings.Broker.Applications[$index].AllowedOperations = @()
    $settings.Broker.Applications[$index].AllowedDataProtectionContexts = @()
    $settings.Broker.Applications[$index].GatewayGrants = @()
    Write-Settings $settings
    Write-Output ('APPLICATION_REVOKED=' + $ApplicationRegistrationId + ' NEXT=START')
    return
}
if ($Command -eq 'Update') {
    Assert-ExpectedPackage
    & $PSCommandPath -Command Stop -Instance $Instance
    # A failed copy must never leave first-install initialization enabled.
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $settings.Broker.InitializeDataKeys = $false
    Write-Settings $settings
    Copy-Published $BrokerPublishDirectory $brokerDirectory
    Copy-Published $SamplePublishDirectory $sampleDirectory
    if (-not [string]::IsNullOrWhiteSpace($AdopterPublishDirectory) -and (Test-Path -LiteralPath $AdopterPublishDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $adopterDirectory -Force | Out-Null
        Copy-Published $AdopterPublishDirectory $adopterDirectory
    }
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $settings.Broker.InitializeDataKeys = $false
    foreach ($application in @($settings.Broker.Applications)) {
        if ($application.RegistrationId -ceq 'local-sample') {
            $application.ExecutablePaths = @($sample)
            $application.ExecutableSha256 = @((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash)
        }
    }
    Write-Settings $settings
}
if ($owned.State -ne 'Running' -or $Command -eq 'Update') { Invoke-ServiceAction 'Start' }
(Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
if ($settings.Broker.InitializeDataKeys) {
    $settings.Broker.InitializeDataKeys = $false
    Write-Settings $settings
}
# SCM readiness is not an application authorization probe. The setup administrator
# need not be authorized to invoke; run the shipped sample under the registered user.
Write-Output 'START=RUNNING NEXT=APPLICATION_STATUS'
