# Tests the shipped ownership and Stop control flow with a simulated SCM. No service is installed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '..\..\..\deploy\windows\Invoke-LocalBroker.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'SCRIPT_PARSE_FAILED' }
foreach ($scriptFile in @('Build-LocalBrokerPackage.ps1', 'Test-LocalBrokerPackage.ps1', 'Test-LocalBrokerWindowsDelivery.ps1', 'Test-LocalBrokerCredentialAdoption.ps1', 'Test-LocalBrokerAdopterAdministration.ps1')) {
    $path = Join-Path $PSScriptRoot ('..\..\..\eng\' + $scriptFile)
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'DELIVERY_SCRIPT_PARSE_FAILED' }
}
foreach ($functionName in @('Assert-NoReparse', 'Get-OwnedService', 'Get-ApplicationUserSid', 'Assert-ExpectedPackage', 'Write-Settings',
    'Read-Settings', 'Assert-ServiceStoppedForApplicationChange', 'Get-CanonicalApplicationExecutable', 'Get-ApplicationOperations',
    'Get-ApplicationContexts', 'Get-ApplicationIndex', 'New-ApplicationPolicy')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$stopBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Stop''' }, $false)
if (-not $stopBranch) { throw 'STOP_CONTROL_FLOW_NOT_FOUND' }
$stop = [ScriptBlock]::Create($stopBranch.Extent.Text)
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('broker-lifecycle-test-' + [guid]::NewGuid().ToString('N'))
$root = Join-Path $fixture 'install'; $data = Join-Path $fixture 'data'; $marker = Join-Path $root 'installation.json'
$name = 'SecureIntegrationBroker.Local.fixture'
$binaryPath = '"' + (Join-Path $root 'broker.exe') + '"'
$script:service = $null; $script:stops = 0; $script:copies = 0; $script:copySawInitializationDisabled = $false
function Get-CimInstance { param($ClassName, $Filter) return $script:service }
function Invoke-ServiceAction { param($Action) if ($Action -cne 'Stop') { throw 'UNEXPECTED_SCM_MUTATION' }; $script:stops++; $script:service.State = 'Stopped' }
function Get-Service { param($Name) return [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State, $Timeout) if ($State -ne 'Stopped') { throw 'UNEXPECTED_WAIT' } } -PassThru }
function Assert([bool] $Condition) { if (-not $Condition) { throw ('LIFECYCLE_ASSERTION_FAILED: ' + (Get-PSCallStack)[1].ScriptLineNumber) } }
function ExpectDenied { param([scriptblock] $Action) try { & $Action | Out-Null } catch { Assert ($_.Exception.Message -like 'LOCAL_BROKER_*'); return }; throw 'OWNERSHIP_WAS_NOT_DENIED' }
try {
    New-Item -ItemType Directory -Path $root, $data -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $data 'preserve.bin'), 'synthetic fixture marker')
    ExpectDenied { Get-OwnedService }
    $record = @{ service = $name; root = $root; data = $data; binaryPath = $binaryPath }
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    $owned = Get-OwnedService; $Command = 'Stop'; & $stop | Out-Null
    Assert ($script:stops -eq 0)
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Running' }
    $owned = Get-OwnedService; & $stop | Out-Null
    $owned = Get-OwnedService; & $stop | Out-Null
    Assert ($script:stops -eq 1)
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    $script:service.PathName = 'foreign.exe'
    ExpectDenied { Get-OwnedService }
    Assert ($script:stops -eq 1)
    $script:service = $null
    $record.data = Join-Path $fixture 'foreign'
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    ExpectDenied { Get-OwnedService }
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    Write-Output 'STOP_ABSENT_NORMAL_REPEAT_OWNERSHIP=PASS (simulated SCM)'
    $ApplicationUserSid = ''
    ExpectDenied { Get-ApplicationUserSid }
    $ApplicationUserSid = 'S-1-5-32-544'
    ExpectDenied { Get-ApplicationUserSid }
    $ApplicationUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert ((Get-ApplicationUserSid) -ceq $ApplicationUserSid)
    Write-Output 'EXPLICIT_APPLICATION_ACCOUNT_SID=PASS'

    # Reuse AST extraction to execute the gate's actual account parameter binding.
    # Only its explicit -WhatIf command is allowed; no account/service/files are created.
    $adoptionPath = Join-Path $PSScriptRoot '..\..\..\eng\Test-LocalBrokerCredentialAdoption.ps1'
    $adoptionAst = [Management.Automation.Language.Parser]::ParseFile($adoptionPath, [ref]$tokens, [ref]$errors)
    $binding = $adoptionAst.Find({ param($node) $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'New-LocalUser' -and @($node.CommandElements | Where-Object {
            $_ -is [Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ceq 'WhatIf' }).Count -eq 1 }, $true)
    Assert ($null -ne $binding)
    $ephemeral = $adoptionAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-EphemeralValue' }, $true)
    . ([ScriptBlock]::Create($ephemeral.Extent.Text))
    $AccountName = 'BrokerCred0905'
    $secret = ConvertTo-SecureString ((New-EphemeralValue) + '-aA1!') -AsPlainText -Force
    try {
        foreach ($Instance in @('credential-20260905', ('credential-' + ('x' * 25)))) {
            $AccountName = if ($Instance.Length -eq 36) { 'BrokerCred12345678' } else { 'BrokerCred0905' }
            foreach ($assignment in $adoptionAst.EndBlock.Statements | Where-Object {
                $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
                $_.Left.Extent.Text -cin @('$accountDescription', '$accountParameters') }) {
                . ([ScriptBlock]::Create($assignment.Extent.Text))
            }
            Assert ($accountDescription.Length -le 48)
            & ([ScriptBlock]::Create($binding.Extent.Text)) | Out-Null
        }
        $accountParameters.Description = 'Task-owned Local Broker credential adoption credential-20260905'
        $denied = $false
        try { & ([ScriptBlock]::Create($binding.Extent.Text)) | Out-Null }
        catch { $denied = $_.Exception.GetType().Name -ceq 'ParameterBindingValidationException' }
        Assert $denied
        Write-Output 'CREDENTIAL_GATE_REAL_CMDLET_BINDING_DEFAULT_MAX_AND_PRIOR_FAILURE=PASS (WhatIf only)'
    }
    finally { $secret.Dispose() }

    $stderrDefinition = $adoptionAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-ChildStderrKind' }, $true)
    . ([ScriptBlock]::Create($stderrDefinition.Extent.Text))
    $progressXml = '#< CLIXML' + "`n" + '<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><S>synthetic progress</S></Obj></Objs>'
    Assert ((Get-ChildStderrKind '') -ceq 'empty')
    Assert ((Get-ChildStderrKind $progressXml) -ceq 'progress-only-clixml')
    Assert ((Get-ChildStderrKind ($progressXml.Replace('S="progress"', 'S="Error"'))) -ceq 'other')
    Assert ((Get-ChildStderrKind ($progressXml.Replace('</Objs>', '<S S="Error">synthetic error</S></Objs>'))) -ceq 'other')
    Assert ((Get-ChildStderrKind '#< CLIXML malformed') -ceq 'other')
    Assert ((Get-ChildStderrKind ('#< CLIXML' + "`n" + '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///forbidden">]><x>&e;</x>')) -ceq 'other')
    Assert ((Get-ChildStderrKind ('x' * 32769)) -ceq 'oversized')
    Write-Output 'CREDENTIAL_CHILD_PROGRESS_ERRORS_MALFORMED_DTD_AND_BOUND=PASS'

    $continuation = $adoptionAst.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -ceq '$ContinueAccountSid' }
    Assert ($null -ne $continuation)
    $ContinueAccountSid = 'S-1-5-21-1-2-3-1001'
    $existingService = [pscustomobject]@{ State = 'Stopped' }
    foreach ($existingUser in @($null, [pscustomobject]@{ SID = [pscustomobject]@{ Value = 'foreign' }; Enabled = $false })) {
        $denied = $false
        try { & ([ScriptBlock]::Create($continuation.Extent.Text)) | Out-Null }
        catch { $denied = $_.Exception.Message -ceq 'CREDENTIAL_GATE_CONTINUATION_OWNERSHIP_DENIED' }
        Assert $denied
    }
    Write-Output 'CREDENTIAL_CONTINUATION_FOREIGN_OR_MISSING_ACCOUNT_DENIED=PASS (no state access)'

    # Read-only Framework reproduction: even Remove on the lazy getter copies the parent block.
    # Inspect only null state and a comparison boolean; never print environment contents or log on.
    $environmentAccess = @($adoptionAst.FindAll({ param($node) $node -is [Management.Automation.Language.MemberExpressionAst] -and
        $node.Member.Extent.Text -cin @('Environment', 'EnvironmentVariables') }, $true))
    Assert ($environmentAccess.Count -eq 0)
    $environmentField = [Diagnostics.ProcessStartInfo].GetField('environmentVariables', [Reflection.BindingFlags]'Instance,NonPublic')
    if ($null -ne $environmentField) {
        $profileProbe = [Diagnostics.ProcessStartInfo]::new()
        $profileProbe.UserName = $AccountName
        $profileProbe.LoadUserProfile = $true
        $profileProbe.UseShellExecute = $false
        $profileProbe.RedirectStandardOutput = $true
        $profileProbe.RedirectStandardError = $true
        Assert ($null -eq $environmentField.GetValue($profileProbe))
        $profileProbe.EnvironmentVariables.Remove('PSModulePath')
        $copiedEnvironment = $environmentField.GetValue($profileProbe)
        Assert ($null -ne $copiedEnvironment -and $copiedEnvironment['USERPROFILE'] -ceq $env:USERPROFILE)
        Write-Output 'CREDENTIAL_FRAMEWORK_LAZY_PARENT_ENVIRONMENT_REGRESSION=PASS (no process or logon)'
    } else {
        Write-Output 'CREDENTIAL_FRAMEWORK_LAZY_PARENT_ENVIRONMENT_REGRESSION=SKIP (private field unavailable; script environment access remains denied)'
    }

    # Execute the shipped update branch with simulated process/SCM/copy failure.
    # The real settings write must disable initialization before the first copy.
    $settingsPath = Join-Path $root 'appsettings.json'
    Write-Settings @{ Broker = @{ InitializeDataKeys = $true; InstallationId = 'preserve-id'; Applications = @(@{ AllowedUserSids = @($ApplicationUserSid) }) } }
    $updateBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Update''' }, $false)
    Assert ($null -ne $updateBranch)
    function Copy-Published {
        param($Source, $Destination)
        $script:copies++
        $persisted = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        Assert (-not $persisted.Broker.InitializeDataKeys)
        $script:copySawInitializationDisabled = $true
        throw 'LOCAL_BROKER_COPY_FIXTURE_FAILURE'
    }
    $updatePackage = Join-Path $fixture 'update-package'
    $BrokerPublishDirectory = Join-Path $updatePackage 'broker'
    $SamplePublishDirectory = Join-Path $updatePackage 'sample'
    $AdopterPublishDirectory = Join-Path $updatePackage 'adopter'
    New-Item -ItemType Directory -Path $BrokerPublishDirectory, $SamplePublishDirectory -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $BrokerPublishDirectory 'SecureIntegration.Broker.Service.exe'), 'synthetic-broker')
    [IO.File]::WriteAllText((Join-Path $SamplePublishDirectory 'SecureIntegration.Samples.LocalBroker.exe'), 'synthetic-sample')
    $updatePackageFiles = @(Get-ChildItem -LiteralPath $updatePackage -Recurse -File | ForEach-Object {
        @{ path = $_.FullName.Substring($updatePackage.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $ExpectedSourceCommit = 'b' * 40
    [IO.File]::WriteAllText((Join-Path $updatePackage 'package-manifest.json'), (@{ schemaVersion = 1; product = 'SecureIntegration.LocalBroker'; sourceCommit = $ExpectedSourceCommit; runtimeIdentifier = 'win-x64'; selfContained = $true; integrity = 'SHA-256 inventory, not a signature or publisher authentication'; files = $updatePackageFiles } | ConvertTo-Json -Depth 5))
    $ExpectedManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $updatePackage 'package-manifest.json') -Algorithm SHA256).Hash
    $brokerDirectory = $root
    Assert-ExpectedPackage
    $approvedManifestHash = $ExpectedManifestSha256
    $ExpectedManifestSha256 = ''
    ExpectDenied { Assert-ExpectedPackage }
    $ExpectedManifestSha256 = $approvedManifestHash
    $ExpectedSourceCommit = ''
    ExpectDenied { Assert-ExpectedPackage }
    $ExpectedSourceCommit = 'c' * 40
    ExpectDenied { Assert-ExpectedPackage }
    $ExpectedSourceCommit = 'b' * 40
    Assert-ExpectedPackage
    Write-Output 'PACKAGE_EXPECTED_VALUES_MISSING_OR_WRONG_SOURCE_DENIED=PASS'
    $installBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Install''' }, $false)
    Assert ($installBranch.Clauses[0].Item2.Statements[0].Extent.Text -ceq 'Assert-ExpectedPackage')
    Assert ($updateBranch.Clauses[0].Item2.Statements[0].Extent.Text -ceq 'Assert-ExpectedPackage')
    # Reuse the shipped update body, replacing only its subprocess Stop with the existing SCM stub.
    $updatePreflight = [ScriptBlock]::Create(($updateBranch.Clauses[0].Item2.Statements | ForEach-Object {
        if ($_.Extent.Text -ceq '& $PSCommandPath -Command Stop -Instance $Instance') { 'Invoke-ServiceAction ''Stop''' }
        else { $_.Extent.Text }
    }) -join "`n")
    function Assert-UpdatePreflightDenied([string] $Code) {
        $settingsBefore = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
        $stateBefore = (Get-FileHash -LiteralPath (Join-Path $data 'preserve.bin') -Algorithm SHA256).Hash
        $stopsBefore = $script:stops; $copiesBefore = $script:copies
        $denied = $false
        try { & $updatePreflight | Out-Null }
        catch { $denied = $_.Exception.Message -ceq $Code }
        Assert $denied
        Assert ($script:stops -eq $stopsBefore -and $script:copies -eq $copiesBefore)
        Assert ((Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -ceq $settingsBefore)
        Assert ((Get-FileHash -LiteralPath (Join-Path $data 'preserve.bin') -Algorithm SHA256).Hash -ceq $stateBefore)
    }
    $validBrokerSource = $BrokerPublishDirectory; $validSampleSource = $SamplePublishDirectory
    foreach ($invalidSource in @('', (Join-Path $fixture 'absent-source'), (Join-Path $data 'preserve.bin'))) {
        $BrokerPublishDirectory = $invalidSource
        Assert-UpdatePreflightDenied 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED'
        $BrokerPublishDirectory = $validBrokerSource
        $SamplePublishDirectory = $invalidSource
        Assert-UpdatePreflightDenied 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED'
        $SamplePublishDirectory = $validSampleSource
    }
    Assert-ExpectedPackage
    Write-Output 'PACKAGE_MISSING_OR_NON_DIRECTORY_SOURCES_DENIED_BEFORE_STOP_COPY=PASS'
    # Package preflight and Stop were exercised above; skip only the subprocess
    # invocation of Stop. Every subsequent settings/copy statement is shipped code.
    $updateAfterStop = ($updateBranch.Clauses[0].Item2.Statements | Select-Object -Skip 2 | ForEach-Object { $_.Extent.Text }) -join "`n"
    ExpectDenied { & ([ScriptBlock]::Create($updateAfterStop)) }
    Assert $script:copySawInitializationDisabled
    $persisted = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert (-not $persisted.Broker.InitializeDataKeys -and $persisted.Broker.InstallationId -ceq 'preserve-id')
    Assert ($persisted.Broker.Applications[0].AllowedUserSids[0] -ceq $ApplicationUserSid)
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    Write-Output 'FAILED_UPDATE_DISALLOWS_INITIALIZATION_PRESERVES_STATE=PASS'

    $registerBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''RegisterApplication''' }, $false)
    $inspectBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''InspectApplications''' }, $false)
    $applicationUpdateBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''UpdateApplication''' }, $false)
    $revokeBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''RevokeApplication''' }, $false)
    Assert ($null -ne $registerBranch -and $null -ne $inspectBranch -and $null -ne $applicationUpdateBranch -and $null -ne $revokeBranch)
    $applicationDirectory = Join-Path $root 'adopter'
    $installedSample = Join-Path $root 'sample\SecureIntegration.Samples.LocalBroker.exe'
    New-Item -ItemType Directory -Path $applicationDirectory, (Split-Path -Parent $installedSample) -Force | Out-Null
    [IO.File]::WriteAllText($installedSample, 'synthetic-sample')
    $adopterExe = Join-Path $applicationDirectory 'SecureIntegration.Samples.LocalBrokerAdopter.exe'
    $adopterV2 = Join-Path $applicationDirectory 'SecureIntegration.Samples.LocalBrokerAdopter.v2.exe'
    [IO.File]::WriteAllText($adopterExe, 'synthetic-adopter-v1')
    [IO.File]::WriteAllText($adopterV2, 'synthetic-adopter-v2')
    $settings = @{ Broker = @{ InitializeDataKeys = $true; InstallationId = 'preserve-id'; Gateway = @{ Enabled = $false }; Applications = @(@{
        RegistrationId = 'local-sample'; AllowedUserSids = @($ApplicationUserSid); ExecutablePaths = @($installedSample)
        ExecutableSha256 = @((Get-FileHash -LiteralPath $installedSample -Algorithm SHA256).Hash)
        AllowedOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
        AllowedDataProtectionContexts = @(@{ Purpose = 'sample'; ContentType = 'text/plain' })
        GatewayGrants = @()
    }) } }
    Write-Settings $settings
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Stopped' }
    $owned = $script:service
    $ApplicationRegistrationId = 'adopter-eval'
    $ApplicationExecutablePath = $adopterExe
    $ApplicationOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
    $ApplicationDataContext = @('adopter-secret:text/plain')
    $beforeRegisterData = (Get-FileHash -LiteralPath (Join-Path $data 'preserve.bin') -Algorithm SHA256).Hash
    $Command = 'RegisterApplication'
    & ([ScriptBlock]::Create($registerBranch.Extent.Text)) | Out-Null
    $registered = Read-Settings
    Assert ($registered.Broker.InitializeDataKeys)
    Assert (@($registered.Broker.Applications).Count -eq 2)
    $appIndex = Get-ApplicationIndex $registered 'adopter-eval'
    Assert ($appIndex -eq 1)
    Assert ($registered.Broker.Applications[$appIndex].AllowedUserSids[0] -ceq $ApplicationUserSid)
    Assert ($registered.Broker.Applications[$appIndex].ExecutablePaths[0] -ceq $adopterExe)
    Assert ($registered.Broker.Applications[$appIndex].ExecutableSha256[0] -ceq (Get-FileHash -LiteralPath $adopterExe -Algorithm SHA256).Hash)
    Assert ($registered.Broker.Applications[$appIndex].AllowedDataProtectionContexts[0].Purpose -ceq 'adopter-secret')
    $Command = 'InspectApplications'
    $inspectJson = & ([ScriptBlock]::Create($inspectBranch.Extent.Text))
    Assert (($inspectJson | Out-String) -match 'adopter-eval')
    $ApplicationExecutablePath = $adopterV2
    $ApplicationUserSid = ''
    $Command = 'UpdateApplication'
    & ([ScriptBlock]::Create($applicationUpdateBranch.Extent.Text)) | Out-Null
    $updated = Read-Settings
    Assert ($updated.Broker.InitializeDataKeys)
    Assert ($updated.Broker.Applications[$appIndex].RegistrationId -ceq 'adopter-eval')
    Assert ($updated.Broker.Applications[$appIndex].ExecutablePaths[0] -ceq $adopterV2)
    Assert ($updated.Broker.Applications[$appIndex].ExecutableSha256[0] -ceq (Get-FileHash -LiteralPath $adopterV2 -Algorithm SHA256).Hash)
    Assert ($updated.Broker.Applications[0].RegistrationId -ceq 'local-sample')
    $Command = 'RevokeApplication'
    & ([ScriptBlock]::Create($revokeBranch.Extent.Text)) | Out-Null
    $revoked = Read-Settings
    Assert ($revoked.Broker.InitializeDataKeys)
    Assert (@($revoked.Broker.Applications).Count -eq 2)
    Assert ($revoked.Broker.Applications[$appIndex].RegistrationId -ceq 'adopter-eval')
    Assert (@($revoked.Broker.Applications[$appIndex].AllowedUserSids).Count -eq 0)
    Assert (@($revoked.Broker.Applications[$appIndex].AllowedOperations).Count -eq 0)
    Assert (@($revoked.Broker.Applications[$appIndex].AllowedDataProtectionContexts).Count -eq 0)
    Assert ((Get-FileHash -LiteralPath (Join-Path $data 'preserve.bin') -Algorithm SHA256).Hash -ceq $beforeRegisterData)
    Write-Output 'APPLICATION_REGISTER_INSPECT_UPDATE_REVOKE_PRESERVES_STATE=PASS (settings only)'

    $settingsBeforeInvalid = (Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash
    $ApplicationExecutablePath = Join-Path $applicationDirectory 'dotnet.exe'
    [IO.File]::WriteAllText($ApplicationExecutablePath, 'synthetic-generic-host')
    $ApplicationUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ApplicationDataContext = @('adopter-secret:text/plain')
    $Command = 'RegisterApplication'
    ExpectDenied { & ([ScriptBlock]::Create($registerBranch.Extent.Text)) }
    Assert ((Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -ceq $settingsBeforeInvalid)
    $script:service.State = 'Running'
    $ApplicationRegistrationId = 'another-adopter'
    $ApplicationExecutablePath = $adopterExe
    $Command = 'RegisterApplication'
    ExpectDenied { & ([ScriptBlock]::Create($registerBranch.Extent.Text)) }
    Assert ((Get-FileHash -LiteralPath $settingsPath -Algorithm SHA256).Hash -ceq $settingsBeforeInvalid)
    $script:service.State = 'Stopped'
    Write-Output 'APPLICATION_INVALID_OR_RUNNING_CHANGE_DENIED_WITHOUT_PARTIAL_POLICY=PASS'

    $ExpectedManifestSha256 = '0' * 64
    ExpectDenied { Assert-ExpectedPackage }
    Assert ((Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).Broker.InstallationId -ceq 'preserve-id')
    Write-Output 'UPDATE_PACKAGE_EXPECTED_MANIFEST_REQUIRED_AND_MISMATCH_DENIED=PASS'

    $packageFixture = Join-Path $fixture 'package'
    foreach ($component in @('broker', 'sample')) {
        $componentPath = Join-Path $packageFixture $component
        New-Item -ItemType Directory -Path $componentPath -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $componentPath 'coreclr.dll'), 'synthetic-not-a-runtime')
        [IO.File]::WriteAllText((Join-Path $componentPath 'synthetic.runtimeconfig.json'), '{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.6"}]}}')
    }
    $packageFiles = @(Get-ChildItem -LiteralPath $packageFixture -Recurse -File | ForEach-Object {
        @{ path = $_.FullName.Substring($packageFixture.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $packageManifest = @{ schemaVersion = 1; product = 'SecureIntegration.LocalBroker'; sourceCommit = ('a' * 40); runtimeIdentifier = 'win-x64'; selfContained = $true; integrity = 'SHA-256 inventory, not a signature or publisher authentication'; files = $packageFiles }
    [IO.File]::WriteAllText((Join-Path $packageFixture 'package-manifest.json'), ($packageManifest | ConvertTo-Json -Depth 5))
    $validator = Join-Path $PSScriptRoot '..\..\..\eng\Test-LocalBrokerPackage.ps1'
    $packageManifestHash = (Get-FileHash -LiteralPath (Join-Path $packageFixture 'package-manifest.json') -Algorithm SHA256).Hash
    & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) -ExpectedManifestSha256 $packageManifestHash | Out-Null
    $BrokerPublishDirectory = Join-Path $packageFixture 'broker'
    $SamplePublishDirectory = Join-Path $packageFixture 'sample'
    $ExpectedSourceCommit = 'a' * 40; $ExpectedManifestSha256 = $packageManifestHash
    Assert-ExpectedPackage
    $unlistedFile = Join-Path $BrokerPublishDirectory 'unlisted.dll'
    foreach ($attribute in @([IO.FileAttributes]::Hidden, [IO.FileAttributes]::System)) {
        [IO.File]::WriteAllText($unlistedFile, 'synthetic-unlisted-file')
        try {
            [IO.File]::SetAttributes($unlistedFile, $attribute)
            Assert (([IO.File]::GetAttributes($unlistedFile) -band $attribute) -eq $attribute)
            Assert-UpdatePreflightDenied 'LOCAL_BROKER_PACKAGE_INVENTORY_MISMATCH'
            $denied = $false
            try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null }
            catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_INVENTORY_MISMATCH' }
            Assert $denied
        }
        finally {
            [IO.File]::SetAttributes($unlistedFile, [IO.FileAttributes]::Normal)
            Remove-Item -LiteralPath $unlistedFile
        }
    }
    Assert-ExpectedPackage
    & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedManifestSha256 $ExpectedManifestSha256 | Out-Null
    Write-Output 'PACKAGE_HIDDEN_SYSTEM_EXTRA_FILES_DENIED_BEFORE_STOP_COPY=PASS'
    $denied = $false
    try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) -ExpectedManifestSha256 ('0' * 64) | Out-Null }
    catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_MANIFEST_HASH_MISMATCH' }
    Assert $denied
    $tamper = Join-Path $packageFixture 'broker\coreclr.dll'
    [IO.File]::AppendAllText($tamper, '-tampered')
    $denied = $false
    try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) -ExpectedManifestSha256 $packageManifestHash | Out-Null }
    catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_HASH_MISMATCH' }
    Assert $denied
    [IO.File]::WriteAllText($tamper, 'synthetic-not-a-runtime')
    [IO.File]::WriteAllText((Join-Path $packageFixture 'broker\appsettings.json'), '{}')
    $denied = $false
    try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) | Out-Null }
    catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_INVENTORY_MISMATCH' }
    Assert $denied
    Write-Output 'PACKAGE_TAMPER_AND_UNLISTED_SETTINGS_DENIED=PASS'

    $deliveryPath = Join-Path $PSScriptRoot '..\..\..\eng\Test-LocalBrokerWindowsDelivery.ps1'
    $deliveryAst = [Management.Automation.Language.Parser]::ParseFile($deliveryPath, [ref]$tokens, [ref]$errors)
    foreach ($functionName in @('StateDigest', 'Get-SyntheticBootstrap', 'Assert-BaselineResume')) {
        $definition = $deliveryAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName }, $true)
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }
    function ExpectDeliveryDenied([scriptblock] $Action, [string] $Code) {
        try { & $Action | Out-Null } catch { Assert ($_.Exception.Message.StartsWith($Code, [StringComparison]::Ordinal)); return }
        throw 'DELIVERY_NEGATIVE_ACCEPTED'
    }
    $root = Join-Path $fixture 'resume'; $data = Join-Path $fixture 'resume-data'
    $marker = Join-Path $root 'installation.json'; $settingsPath = Join-Path $root 'broker\appsettings.json'
    $binaryPath = '"' + (Join-Path $root 'broker\SecureIntegration.Broker.Service.exe') + '" --contentRoot "' + (Join-Path $root 'broker') + '"'
    $BaselineBrokerDirectory = Join-Path $fixture 'baseline\broker'; $BaselineSampleDirectory = Join-Path $fixture 'baseline\sample'
    New-Item -ItemType Directory -Path (Join-Path $data 'keys'), (Join-Path $root 'broker'), (Join-Path $root 'sample'), $BaselineBrokerDirectory, $BaselineSampleDirectory -Force | Out-Null
    foreach ($component in @('broker', 'sample')) {
        $leaf = if ($component -ceq 'broker') { 'SecureIntegration.Broker.Service.exe' } else { 'SecureIntegration.Samples.LocalBroker.exe' }
        [IO.File]::WriteAllText((Join-Path $fixture ('baseline\' + $component + '\' + $leaf)), 'synthetic-binary')
        Copy-Item -LiteralPath (Join-Path $fixture ('baseline\' + $component + '\' + $leaf)) -Destination (Join-Path $root $component)
    }
    $record = @{ service = $name; root = $root; data = $data; binaryPath = $binaryPath; installationId = 'preserved-synthetic-installation' }
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    [IO.File]::WriteAllText((Join-Path $data 'keys\z[1].bin'), 'synthetic-wrapped-state')
    [IO.File]::WriteAllText((Join-Path $data 'keys\active.txt'), 'synthetic-version')
    $expectedHashes = foreach ($file in @($marker, (Join-Path $data 'keys\active.txt'), (Join-Path $data 'keys\z[1].bin'))) {
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    }
    $retained = StateDigest
    Assert ($retained -ceq ($expectedHashes -join ',') -and $retained.Split(',').Count -eq 3)
    Assert ((StateDigest) -ceq $retained)
    Write-Output 'PS51_STATE_DIGEST_MULTIPLE_LITERAL_PATHS=PASS'

    $installedSample = Join-Path $root 'sample\SecureIntegration.Samples.LocalBroker.exe'
    $settings = @{ Broker = @{ ServiceName = $name; PipeName = $name; InstallationId = $record.installationId; DataDirectory = $data;
        InitializeDataKeys = $false; Gateway = @{ Enabled = $false }; Applications = @(@{
            RegistrationId = 'local-sample'; AllowedUserSids = @($ApplicationUserSid); ExecutablePaths = @($installedSample)
            ExecutableSha256 = @((Get-FileHash -LiteralPath $installedSample -Algorithm SHA256).Hash)
            AllowedOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
            AllowedDataProtectionContexts = @(@{ Purpose = 'sample'; ContentType = 'text/plain' })
        }) } }
    Write-Settings $settings
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Stopped' }
    $BaselineEnvelopeForUpgrade = $false
    $stopsBefore = $script:stops
    Assert-BaselineResume
    Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
    $script:service.State = 'Running'
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_RESUME_REQUIRES_OWNED_STOPPED_BASELINE'
    $BaselineEnvelopeForUpgrade = $true
    Assert-BaselineResume
    $script:service.State = 'Stopped'
    $BaselineEnvelopeForUpgrade = $false
    $script:service.PathName = 'foreign.exe'
    ExpectDenied { Assert-BaselineResume }
    $script:service.PathName = $binaryPath
    [IO.File]::AppendAllText($installedSample, '-different-build')
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_FILES_MISMATCH'
    [IO.File]::WriteAllText($installedSample, 'synthetic-binary')
    $settings.Broker.InitializeDataKeys = $true
    Write-Settings $settings
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_CONFIGURATION_MISMATCH'
    $settings.Broker.InitializeDataKeys = $false
    $settings.Broker.Applications[0].AllowedUserSids = @('foreign-sid')
    Write-Settings $settings
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_CONFIGURATION_MISMATCH'
    Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
    Write-Output 'BASELINE_RESUME_OWNERSHIP_BUILD_POLICY_STATE=PASS (read-only simulated SCM)'

    $SyntheticBootstrapDirectory = Join-Path $fixture 'synthetic-bootstrap'
    New-Item -ItemType Directory -Path (Join-Path $SyntheticBootstrapDirectory 'certificates') -Force | Out-Null
    $rsa = [Security.Cryptography.RSACng]::new(2048)
    $certificate = $null
    $previousCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=M3 Synthetic Root fixture', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
        [IO.File]::WriteAllBytes((Join-Path $SyntheticBootstrapDirectory 'certificates\ca.crt'), $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $document = @{ sampleConnector = @{ connectorId = 'sample-secure-service'; state = 'Published' }; activationCodeId = [guid]::NewGuid().ToString('D'); activationCode = 'synthetic-single-use'; expiresAtUtc = [DateTime]::UtcNow.AddMinutes(30).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
        $documentPath = Join-Path $SyntheticBootstrapDirectory 'provisioning.json'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('it-IT')
        $validated = Get-SyntheticBootstrap
        Assert ($validated.Expires -gt [DateTimeOffset]::UtcNow)
        $validated.Certificate.Dispose()
        $goodDirectory = $SyntheticBootstrapDirectory
        $SyntheticBootstrapDirectory += '-missing'
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        $SyntheticBootstrapDirectory = $goodDirectory
        $document.expiresAtUtc = '06/09/2026 08:37:08'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        $document.expiresAtUtc = '2000-01-01T00:00:00.0000000Z'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
        Write-Output 'PS51_BOOTSTRAP_PREFLIGHT_ISO_CULTURE_PATH_EXPIRY=PASS'
    }
    finally {
        [Threading.Thread]::CurrentThread.CurrentCulture = $previousCulture
        if ($certificate) { $certificate.Dispose() }
        $rsa.Dispose()
    }
}
finally {
    if (([IO.Path]::GetFullPath($fixture)).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
