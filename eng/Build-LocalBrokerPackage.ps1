# Build-host tool only. The extracted package requires neither the repository nor an SDK.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [string] $DotNetPath = 'dotnet'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
    $output.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $output)) { throw 'BROKER_PACKAGE_REQUIRES_NEW_EXTERNAL_DIRECTORY' }
$head = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $ExpectedSourceCommit) { throw 'BROKER_PACKAGE_SOURCE_MISMATCH' }
$dirty = @(& git -C $root status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'BROKER_PACKAGE_SOURCE_MUST_BE_CLEAN' }
$version = ([xml](Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw)).SelectSingleNode('/Project/PropertyGroup/ProductVersion').InnerText
$packageName = 'local-broker-' + $version + '-win-x64-' + $head.Substring(0, 12)
$stage = Join-Path $output $packageName
New-Item -ItemType Directory -Path $stage | Out-Null
function Invoke-Checked([string[]] $Arguments) {
    & $DotNetPath @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'BROKER_PACKAGE_BUILD_FAILED' }
}
$components = @{
    broker = 'src/Broker/Broker.Service/Broker.Service.csproj'
    sample = 'samples/LocalBroker/LocalBroker.csproj'
    adopter = 'samples/LocalBrokerAdopter/LocalBrokerAdopter.csproj'
}
foreach ($component in @('broker', 'sample', 'adopter')) {
    $project = Join-Path $root $components[$component]
    # RID-specific resolution is isolated from the repository's portable locks.
    # Freeze that resolution, then use only its locked assets for publication.
    $properties = @('-r', 'win-x64', '-p:SelfContained=true', '-p:NuGetLockFilePath=obj/windows-package-win-x64.lock.json')
    Invoke-Checked (@('restore', $project) + $properties)
    Invoke-Checked (@('restore', $project, '--locked-mode') + $properties)
    $published = Join-Path $output ('.build/' + $component)
    Invoke-Checked (@('publish', $project, '-c', 'Release', '--no-restore', '-o', $published,
        '-p:DebugType=None', '-p:DebugSymbols=false', '-p:GenerateDocumentationFile=false',
        '-p:ContinuousIntegrationBuild=true', ('-p:PathMap=' + $root + '=/_/src')) + $properties)
    $destination = Join-Path $stage $component
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $published -Recurse -File) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'BROKER_PACKAGE_REPARSE_DENIED' }
        $relative = $file.FullName.Substring($published.Length + 1)
        # Product-only closed file kinds; notably no appsettings or fixture data.
        if ($file.Extension -notin @('.dll', '.exe') -and $file.Name -notlike '*.deps.json' -and
            $file.Name -notlike '*.runtimeconfig.json' -and $file.Name -notin @('LICENSE.txt', 'THIRD-PARTY-NOTICES.txt')) { continue }
        $target = Join-Path $destination $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
    $runtimeConfig = Get-Content -LiteralPath (@(Get-ChildItem -LiteralPath $destination -Filter '*.runtimeconfig.json')[0].FullName) -Raw | ConvertFrom-Json
    $runtimeVersion = @($runtimeConfig.runtimeOptions.includedFrameworks | Where-Object { $_.name -ceq 'Microsoft.NETCore.App' })[0].version
    $assets = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $project) 'obj/project.assets.json') -Raw | ConvertFrom-Json
    $runtimePacks = @($assets.packageFolders.PSObject.Properties.Name | ForEach-Object { Join-Path $_ ('microsoft.netcore.app.runtime.win-x64/' + $runtimeVersion) } | Where-Object { Test-Path -LiteralPath $_ })
    if ($runtimePacks.Count -ne 1) { throw 'BROKER_PACKAGE_RUNTIME_NOTICES_MISSING' }
    foreach ($notice in @('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT')) {
        Copy-Item -LiteralPath (Join-Path $runtimePacks[0] $notice) -Destination (Join-Path $destination ('runtime-' + $notice.ToLowerInvariant()))
    }
}
Copy-Item -LiteralPath (Join-Path $root 'deploy/windows/Invoke-LocalBroker.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'deploy/windows/README.md') -Destination $stage
foreach ($notice in @('LICENSE', 'LICENSE-APACHE-2.0', 'NOTICE')) { Copy-Item -LiteralPath (Join-Path $root $notice) -Destination $stage }
$files = @(Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($stage.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$manifest = [ordered]@{
    schemaVersion = 1; product = 'SecureIntegration.LocalBroker'; version = [string]$version
    sourceCommit = $head; runtimeIdentifier = 'win-x64'; selfContained = $true
    integrity = 'SHA-256 inventory, not a signature or publisher authentication'
    dependencies = @('broker/SecureIntegration.Broker.Service.deps.json', 'sample/SecureIntegration.Samples.LocalBroker.deps.json', 'adopter/SecureIntegration.Samples.LocalBrokerAdopter.deps.json')
    files = $files
}
[IO.File]::WriteAllText((Join-Path $stage 'package-manifest.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
$manifestHash = (Get-FileHash -LiteralPath (Join-Path $stage 'package-manifest.json') -Algorithm SHA256).Hash
& (Join-Path $PSScriptRoot 'Test-LocalBrokerPackage.ps1') -PackageDirectory $stage -ExpectedSourceCommit $head -ExpectedManifestSha256 $manifestHash
$archive = Join-Path $output ($packageName + '.zip')
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
[IO.File]::WriteAllText(($archive + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($archive) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output ('BROKER_PACKAGE=PASS SOURCE=' + $head + ' MANIFEST_SHA256=' + $manifestHash + ' ARCHIVE=' + $archive)
