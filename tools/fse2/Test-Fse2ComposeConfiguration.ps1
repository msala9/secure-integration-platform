[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ProviderManifestPath,
    [Parameter(Mandatory = $true)][string] $MaterialDirectory,
    [Parameter(Mandatory = $true)][string] $AuthCertificateVersion,
    [Parameter(Mandatory = $true)][string] $SignCertificateVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
$manifest = Get-Fse2PathSnapshot -Path $ProviderManifestPath -Kind File -RepositoryRoot $root `
    -ErrorCodePrefix 'FSE2_COMPOSE_MANIFEST_PATH' -MaximumBytes 262144
$material = Get-Fse2PathSnapshot -Path $MaterialDirectory -Kind Directory -RepositoryRoot $root `
    -ErrorCodePrefix 'FSE2_COMPOSE_MATERIAL_PATH'
Assert-Fse2PathSnapshot -Snapshot $manifest | Out-Null
Assert-Fse2PathSnapshot -Snapshot $material | Out-Null
if ([string]::IsNullOrWhiteSpace($AuthCertificateVersion) -or [string]::IsNullOrWhiteSpace($SignCertificateVersion)) {
    throw 'FSE2_COMPOSE_CERTIFICATE_VERSION_INVALID'
}

$composeFiles = @(
    [IO.Path]::GetFullPath((Join-Path $root 'deploy\m3\docker-compose.m3a.yml')),
    [IO.Path]::GetFullPath((Join-Path $root 'deploy\m5\docker-compose.m5.yml')),
    [IO.Path]::GetFullPath((Join-Path $root 'deploy\fse2\docker-compose.fse2-local.yml')))
foreach ($composeFile in $composeFiles) {
    if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) { throw 'FSE2_COMPOSE_ALLOWLIST_INVALID' }
}

function New-SyntheticValue {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return [Convert]::ToBase64String($bytes) }
    finally { $rng.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
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
        throw 'FSE2_COMPOSE_ENVIRONMENT_RESTORE_FAILED'
    }
}
$environmentId = [Guid]::NewGuid().ToString('D')
$temporaryBase = [IO.Path]::GetTempPath().TrimEnd('\', '/')
$values = [ordered]@{
    M3_POSTGRES_ADMIN_PASSWORD = New-SyntheticValue
    M3_POSTGRES_RUNTIME_PASSWORD = New-SyntheticValue
    M3_ACTIVATION_HMAC_BASE64 = New-SyntheticValue
    M3_VENDOR_CLIENT_PFX_BASE64 = New-SyntheticValue
    M3_WRONG_VENDOR_CLIENT_PFX_BASE64 = New-SyntheticValue
    M3_CERTIFICATE_PASSWORD = New-SyntheticValue
    M3_SYNTHETIC_VAULT_TOKEN = New-SyntheticValue
    M3_VENDOR_API_KEY = New-SyntheticValue
    M3_VENDOR_CLIENT_THUMBPRINT = ('0' * 64)
    M3_VENDOR_CONTROL_TOKEN = New-SyntheticValue
    M5_POSTGRES_ADMIN_API_PASSWORD = New-SyntheticValue
    M3_RAW_EVIDENCE_DIRECTORY = Join-Path $temporaryBase ('fse2-compose-evidence-' + [Guid]::NewGuid().ToString('N'))
    M3_CERTIFICATE_DIRECTORY = Join-Path $temporaryBase ('fse2-compose-certificates-' + [Guid]::NewGuid().ToString('N'))
    FSE2_PROVIDER_MANIFEST_PATH = $manifest.FullPath
    FSE2_PROVIDER_MATERIAL_DIRECTORY = $material.FullPath
    FSE2_TEST_ENVIRONMENT_ID = $environmentId
    M3_PRIMARY_ENVIRONMENT_ID = $environmentId
    M3_SECURITY_ENVIRONMENT_ID = [Guid]::NewGuid().ToString('D')
    FSE2_AUTH_CERT_VERSION = $AuthCertificateVersion
    FSE2_SIGN_CERT_VERSION = $SignCertificateVersion
    FSE2_CONTAINER_RUNTIME_UID = '1654'
}
$previous = @{}
try {
    foreach ($entry in $values.GetEnumerator()) {
        $previous[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    Assert-Fse2PathSnapshot -Snapshot $manifest | Out-Null
    Assert-Fse2PathSnapshot -Snapshot $material | Out-Null
    & docker compose --project-name ('fse2-compose-validator-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)) `
        --file $composeFiles[0] --file $composeFiles[1] --file $composeFiles[2] config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_COMPOSE_CONFIG_FAILED' }
    Write-Host 'FSE2_CANONICAL_COMPOSE_VALIDATOR_PASS'
}
finally {
    foreach ($entry in $previous.GetEnumerator()) {
        Restore-ProcessEnvironmentValue -Name $entry.Key -Value $entry.Value
    }
    foreach ($key in @($values.Keys)) { $values[$key] = $null }
}
