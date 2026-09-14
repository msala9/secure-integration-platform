[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Start', 'Stop')]
    [string] $Phase = 'Validate',
    [string] $ProviderManifestPath,
    [string] $MaterialDirectory,
    [ValidateSet('fse2-national', 'fse2-organization-current-spec')]
    [string] $ConnectorScope = 'fse2-national',
    [Guid] $EnvironmentId = '907cf0ea-d592-43a7-9b42-2bd5b97fe7b4',
    [string] $DotNetPath,
    [string] $QuickstartArtifactRoot,
    [switch] $SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
$compose = Join-Path $root 'deploy\fse2\docker-compose.fse2-local.yml'
$quickstart = Join-Path $root 'tools\m5\Invoke-M5Quickstart.ps1'
$powershell = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'powershell.exe' } else { 'pwsh' }
$allowedComposeFiles = @(
    [IO.Path]::GetFullPath((Join-Path $root 'deploy\m3\docker-compose.m3a.yml')),
    [IO.Path]::GetFullPath((Join-Path $root 'deploy\m5\docker-compose.m5.yml')),
    [IO.Path]::GetFullPath($compose))
foreach ($allowedComposeFile in $allowedComposeFiles) {
    if (-not (Test-Path -LiteralPath $allowedComposeFile -PathType Leaf)) { throw 'FSE2_LOCAL_PROVIDER_COMPOSE_ALLOWLIST_INVALID' }
}

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "FSE2_LOCAL_PROVIDER_COMMAND_FAILED:$File" }
}

function Get-M5QuickstartArtifactFileSnapshot {
    param(
        [Parameter(Mandatory = $true)][string] $ArtifactRoot,
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][long] $MaximumBytes
    )
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $canonicalRoot = [IO.Path]::GetFullPath($ArtifactRoot).TrimEnd($separators)
    $canonicalPath = [IO.Path]::GetFullPath($Path).TrimEnd($separators)
    if (-not $canonicalPath.StartsWith(($canonicalRoot + [IO.Path]::DirectorySeparatorChar), $comparison)) {
        throw 'FSE2_LOCAL_PROVIDER_M5_ARTIFACT_FILE_OUTSIDE_ROOT'
    }
    $pathRoot = [IO.Path]::GetPathRoot($canonicalPath)
    $cursor = $pathRoot
    foreach ($segment in @($canonicalPath.Substring($pathRoot.Length) -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $cursor = Join-Path $cursor $segment
        if (-not (Test-Path -LiteralPath $cursor)) { throw 'FSE2_LOCAL_PROVIDER_M5_ARTIFACT_FILE_MISSING' }
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FSE2_LOCAL_PROVIDER_M5_ARTIFACT_REPARSE_DENIED'
        }
    }
    $file = Get-Item -LiteralPath $canonicalPath -Force
    if ($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) {
        throw 'FSE2_LOCAL_PROVIDER_M5_ARTIFACT_FILE_INVALID'
    }
    return [pscustomobject]@{
        FullPath = $canonicalPath
        Length = [long]$file.Length
        Sha256 = (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash
        ArtifactRoot = $canonicalRoot
        MaximumBytes = $MaximumBytes
    }
}

function Assert-M5QuickstartArtifactFileSnapshot {
    param([Parameter(Mandatory = $true)] $Snapshot)
    $current = Get-M5QuickstartArtifactFileSnapshot -ArtifactRoot $Snapshot.ArtifactRoot -Path $Snapshot.FullPath -MaximumBytes $Snapshot.MaximumBytes
    if ($current.FullPath -cne $Snapshot.FullPath -or $current.Length -ne $Snapshot.Length -or $current.Sha256 -cne $Snapshot.Sha256) {
        throw 'FSE2_LOCAL_PROVIDER_M5_ARTIFACT_FILE_CHANGED'
    }
}

if ($Phase -eq 'Stop') {
    $stopArguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $quickstart,
        '-Phase', 'Stop', '-AdditionalComposeFile', $compose)
    if (-not [string]::IsNullOrWhiteSpace($QuickstartArtifactRoot)) { $stopArguments += @('-ArtifactRoot', $QuickstartArtifactRoot) }
    Invoke-Checked $powershell $stopArguments
    $project = 'secure-integration-m5-quickstart'
    $remainingContainers = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $project))
    $remainingNetworks = @(& docker network ls -q --filter ('label=com.docker.compose.project=' + $project))
    $remainingVolumes = @(& docker volume ls -q --filter ('label=com.docker.compose.project=' + $project))
    if ($LASTEXITCODE -ne 0 -or $remainingContainers.Count -ne 0 -or $remainingNetworks.Count -ne 0 -or $remainingVolumes.Count -ne 0) {
        throw 'FSE2_LOCAL_PROVIDER_CLEANUP_FAILED'
    }
    Write-Host 'FSE2_LOCAL_PROVIDER_STOP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; HELPERS=0'
    return
}

if ([string]::IsNullOrWhiteSpace($ProviderManifestPath) -or [string]::IsNullOrWhiteSpace($MaterialDirectory)) {
    throw 'FSE2_LOCAL_PROVIDER_INPUT_MISSING'
}
if ($Phase -eq 'Start' -and [string]::IsNullOrWhiteSpace($QuickstartArtifactRoot)) {
    throw 'FSE2_LOCAL_PROVIDER_ARTIFACT_ROOT_MISSING'
}
$manifestSnapshot = Get-Fse2PathSnapshot -Path $ProviderManifestPath -Kind File -RepositoryRoot $root `
    -ErrorCodePrefix 'FSE2_LOCAL_PROVIDER_MANIFEST_PATH' -MaximumBytes 262144
$materialSnapshot = Get-Fse2PathSnapshot -Path $MaterialDirectory -Kind Directory -RepositoryRoot $root `
    -ErrorCodePrefix 'FSE2_LOCAL_PROVIDER_MATERIAL_PATH'
$manifestPath = $manifestSnapshot.FullPath
$materialRoot = $materialSnapshot.FullPath
$quickstartArtifactPlan = if ($Phase -eq 'Start') {
    [pscustomobject]@{ FullPath = [IO.Path]::GetFullPath($QuickstartArtifactRoot) }
} else { $null }
$dotnet = if ([string]::IsNullOrWhiteSpace($DotNetPath)) { Join-Path $root '.dotnet\dotnet.exe' } else { [IO.Path]::GetFullPath($DotNetPath) }
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) {
    if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { throw 'FSE2_LOCAL_PROVIDER_DOTNET_INVALID' }
    $dotnet = 'dotnet'
}

if ($EnvironmentId -eq [Guid]::Empty) { throw 'FSE2_LOCAL_ENVIRONMENT_ID_INVALID' }
Assert-Fse2PathSnapshot -Snapshot $manifestSnapshot | Out-Null
Assert-Fse2PathSnapshot -Snapshot $materialSnapshot | Out-Null
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1 -or @($manifest.resources).Count -lt 2) { throw 'FSE2_LOCAL_PROVIDER_MANIFEST_INVALID' }
$auth = @($manifest.resources | Where-Object { $_.id -eq 'fse2-auth' -and $_.kind -eq 'ClientCertificate' })
$sign = @($manifest.resources | Where-Object { $_.id -eq 'fse2-sign' -and $_.kind -eq 'SigningCertificate' })
if ($auth.Count -ne 1 -or $sign.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$auth[0].version) -or
    [string]::IsNullOrWhiteSpace([string]$sign[0].version)) {
    throw 'FSE2_LOCAL_PROVIDER_REQUIRED_RESOURCES_INVALID'
}

function Set-LabEnvironment {
    $values = @{
        FSE2_PROVIDER_MANIFEST_PATH = $manifestPath
        FSE2_PROVIDER_MATERIAL_DIRECTORY = $materialRoot
        FSE2_TEST_ENVIRONMENT_ID = $EnvironmentId.ToString('D')
        M3_PRIMARY_ENVIRONMENT_ID = $EnvironmentId.ToString('D')
        M3_SECURITY_ENVIRONMENT_ID = [Guid]::NewGuid().ToString('D')
        FSE2_AUTH_CERT_VERSION = [string]$auth[0].version
        FSE2_SIGN_CERT_VERSION = [string]$sign[0].version
        FSE2_CONNECTOR_SCOPE = $ConnectorScope
    }
    foreach ($entry in $values.GetEnumerator()) {
        $script:previousLabEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function Restore-ProcessEnvironmentValue {
    param([Parameter(Mandatory = $true)][string] $Name, [AllowNull()][object] $Value)
    if ($null -eq $Value) {
        Remove-Item -LiteralPath ('Env:' + $Name) -ErrorAction SilentlyContinue
    } else {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
    }
    $restored = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (($null -eq $Value -and $null -ne $restored) -or ($null -ne $Value -and $restored -cne $Value)) {
        throw 'FSE2_LOCAL_PROVIDER_ENVIRONMENT_RESTORE_FAILED'
    }
}

function Clear-LabEnvironment {
    foreach ($entry in $script:previousLabEnvironment.GetEnumerator()) {
        Restore-ProcessEnvironmentValue -Name $entry.Key -Value $entry.Value
    }
}

$previousLabEnvironment = @{}
Set-LabEnvironment
try {
    if ($Phase -eq 'Validate') {
        Invoke-Checked $dotnet @('restore', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--locked-mode')
        Invoke-Checked $dotnet @('build', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--configuration', 'Release', '--no-restore')
        Invoke-Checked $dotnet @('test', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--configuration', 'Release', '--no-build', '--no-restore')
        & (Join-Path $PSScriptRoot 'Test-Fse2ComposeConfiguration.ps1') `
            -ProviderManifestPath $manifestPath `
            -MaterialDirectory $materialRoot `
            -AuthCertificateVersion ([string]$auth[0].version) `
            -SignCertificateVersion ([string]$sign[0].version)
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_CANONICAL_COMPOSE_VALIDATOR_FAILED' }
        Write-Host 'FSE2_LOCAL_PROVIDER_VALIDATE_PASS'
        return
    }

    $quickstartArguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $quickstart,
        '-Phase', $Phase, '-AdditionalComposeFile', $compose)
    if ($dotnet -ne 'dotnet') { $quickstartArguments += @('-DotNetPath', $dotnet) }
    if ($null -ne $quickstartArtifactPlan) {
        $quickstartArguments += @('-ArtifactRoot', $quickstartArtifactPlan.FullPath)
    }
    if ($SkipBuild) { $quickstartArguments += '-SkipBuild' }
    Invoke-Checked $powershell $quickstartArguments

    if ($Phase -eq 'Start') {
        $container = (& docker ps --quiet --filter 'label=com.docker.compose.project=secure-integration-m5-quickstart' --filter 'label=com.docker.compose.service=gateway')
        if ($LASTEXITCODE -ne 0 -or @($container).Count -ne 1) { throw 'FSE2_LOCAL_PROVIDER_GATEWAY_NOT_FOUND' }
        $containerId = [string]@($container)[0]
        $readOnly = (& docker inspect $containerId --format '{{.HostConfig.ReadonlyRootfs}}').Trim()
        if ($LASTEXITCODE -ne 0 -or $readOnly -ne 'true') { throw 'FSE2_LOCAL_PROVIDER_READ_ONLY_FAILED' }
        $containerUid = (& docker exec $containerId id -u).Trim()
        if ($LASTEXITCODE -ne 0 -or $containerUid -eq '0') { throw 'FSE2_LOCAL_PROVIDER_NON_ROOT_FAILED' }
        & docker exec $containerId test -r /run/fse2-provider/manifest.json *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_MANIFEST_MOUNT_UNREADABLE' }
        foreach ($mountedMaterialFile in @(
            'auth.p12', 'auth.password', 'auth-leaf.pem',
            'sign.p12', 'sign.password', 'sign-leaf.pem', 'root.pem')) {
            & docker exec $containerId test -r ('/run/fse2-provider/material/' + $mountedMaterialFile) *> $null
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_MATERIAL_MOUNT_UNREADABLE' }
        }
        & docker exec $containerId test -r /app/packs/local-pkcs12/SecureIntegration.Providers.LocalPkcs12.dll *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_PACK_UNREADABLE' }
        & docker exec $containerId test -r /app/packs/healthcare-fse2/SecureIntegration.ConnectorPacks.Healthcare.FSE2.dll *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_VERTICAL_PACK_UNREADABLE' }
        $gatewayCaSnapshot = Get-M5QuickstartArtifactFileSnapshot -ArtifactRoot $quickstartArtifactPlan.FullPath `
            -Path (Join-Path $quickstartArtifactPlan.FullPath 'raw\certificates\ca.crt') -MaximumBytes 1048576
        $curl = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'curl.exe' } else { 'curl' }
        $curlBase = @('--fail', '--silent', '--show-error', '--max-time', '15')
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $curlBase += '--ssl-no-revoke' }
        $curlBase += @('--cacert', $gatewayCaSnapshot.FullPath)
        Assert-M5QuickstartArtifactFileSnapshot -Snapshot $gatewayCaSnapshot
        & $curl @curlBase 'https://localhost:18443/health/live' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_PROVIDER_LIVE_FAILED' }

        $readyDeadline = [DateTimeOffset]::UtcNow.AddMinutes(1)
        $providerReady = $false
        do {
            Assert-M5QuickstartArtifactFileSnapshot -Snapshot $gatewayCaSnapshot
            & $curl @curlBase 'https://localhost:18443/health/ready' *> $null
            if ($LASTEXITCODE -eq 0) { $providerReady = $true; break }
            Start-Sleep -Seconds 2
        } while ([DateTimeOffset]::UtcNow -lt $readyDeadline)
        if (-not $providerReady) { throw 'FSE2_LOCAL_PROVIDER_READY_FAILED' }
        Write-Host 'FSE2_LOCAL_PROVIDER_START_PASS; LIVE_FSE2_CALLS=0'
    }
}
finally {
    Clear-LabEnvironment
}
