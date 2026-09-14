[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PackageDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ExpectedManifestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path.TrimEnd('\')
$manifestPath = Join-Path $package 'package-manifest.json'
if (-not [string]::IsNullOrWhiteSpace($ExpectedManifestSha256) -and
    (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne $ExpectedManifestSha256.ToUpperInvariant()) {
    throw 'BROKER_PACKAGE_MANIFEST_HASH_MISMATCH'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $manifest.sourceCommit -cne $ExpectedSourceCommit -or
    $manifest.product -cne 'SecureIntegration.LocalBroker' -or $manifest.runtimeIdentifier -cne 'win-x64' -or
    -not $manifest.selfContained) { throw 'BROKER_PACKAGE_MANIFEST_INVALID' }
$actual = @(Get-ChildItem -LiteralPath $package -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($package.Length + 1).Replace('\', '/') })
$expected = @($manifest.files.path) + @('package-manifest.json')
if (@(Compare-Object $actual $expected).Count -ne 0 -or @($expected | Select-Object -Unique).Count -ne $expected.Count) {
    throw 'BROKER_PACKAGE_INVENTORY_MISMATCH'
}
foreach ($entry in $manifest.files) {
    if ($entry.path -cnotmatch '^(broker|sample|adopter)/[a-zA-Z0-9_./-]+\.(dll|exe|deps\.json|runtimeconfig\.json|txt)$' -and
        $entry.path -cnotin @('Invoke-LocalBroker.ps1', 'README.md', 'LICENSE', 'LICENSE-APACHE-2.0', 'NOTICE')) { throw 'BROKER_PACKAGE_FILE_DENIED' }
    $path = [IO.Path]::GetFullPath((Join-Path $package $entry.path))
    if (-not $path.StartsWith($package + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'BROKER_PACKAGE_PATH_DENIED' }
    if ((Get-Item -LiteralPath $path).Length -ne $entry.bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $entry.sha256) { throw 'BROKER_PACKAGE_HASH_MISMATCH' }
}
foreach ($component in @('broker', 'sample')) {
    $directory = Join-Path $package $component
    if (-not (Test-Path -LiteralPath (Join-Path $directory 'coreclr.dll'))) { throw 'BROKER_PACKAGE_RUNTIME_MISSING' }
    $runtime = @(Get-ChildItem -LiteralPath $directory -Filter '*.runtimeconfig.json')
    if ($runtime.Count -ne 1) { throw 'BROKER_PACKAGE_RUNTIME_CONFIG_INVALID' }
    $config = Get-Content -LiteralPath $runtime[0].FullName -Raw | ConvertFrom-Json
    if (-not $config.runtimeOptions.includedFrameworks) { throw 'BROKER_PACKAGE_NOT_SELF_CONTAINED' }
}
$adopter = Join-Path $package 'adopter'
if (Test-Path -LiteralPath $adopter) {
    foreach ($required in @('SecureIntegration.Samples.LocalBrokerAdopter.exe', 'SecureIntegration.Samples.LocalBrokerAdopter.deps.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $adopter $required) -PathType Leaf)) { throw 'BROKER_PACKAGE_ADOPTER_APP_INVALID' }
    }
}
Write-Output ('BROKER_PACKAGE_INVENTORY_HASHES_RUNTIME=PASS FILES=' + $actual.Count)
