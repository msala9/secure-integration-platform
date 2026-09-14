# Temporary diagnostic branch: retain only numeric observations and two named outcomes.
$ErrorActionPreference = 'Stop'
$names = @(
    'SecureIntegration.Broker.Integration.Tests.WindowsBrokerIntegrationTests.Incomplete_handshake_releases_connection_and_allows_later_request',
    'SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap.TypedSessionHandshakeRealHttpIntegrationTests.Wave1_IT_Internal_composition_store_authorizer_registry_and_real_restricted_HTTPS_complete_external_admission'
)
$results = @()
if ($env:SIP_SUITE_RESULTS -and (Test-Path -LiteralPath $env:SIP_SUITE_RESULTS)) {
    foreach ($file in Get-ChildItem -LiteralPath $env:SIP_SUITE_RESULTS -Filter *.trx -File -Recurse) {
        [xml]$document = Get-Content -LiteralPath $file.FullName -Raw
        $ids = @{}
        foreach ($definition in $document.SelectNodes("//*[local-name()='UnitTest']")) {
            $name = [string]$definition.TestMethod.className + '.' + [string]$definition.TestMethod.name
            if ($names -ccontains $name) { $ids[[string]$definition.id] = $name }
        }
        foreach ($result in $document.SelectNodes("//*[local-name()='UnitTestResult']")) {
            if (-not $ids.ContainsKey([string]$result.testId)) { continue }
            $outcome = if (@('Passed', 'Failed', 'NotExecuted') -ccontains [string]$result.outcome) { [string]$result.outcome } else { 'Unknown' }
            $results += [ordered]@{
                name = $ids[[string]$result.testId]
                outcome = $outcome
                durationMs = [TimeSpan]::Parse([string]$result.duration).TotalMilliseconds
            }
        }
    }
}
$observations = @{}
$phases = @(
    'test-start', 'test-scope-exit', 'process-sample', 'server-run-start', 'server-run-returned',
    'client-connect-start', 'client-connected-not-proof-of-server-admission', 'partial-handshake-flushed',
    'observer-deadline-start-3000ms', 'observer-deadline-cancelled', 'eof-asserted', 'eof-wait-exit',
    'connection-audit', 'later-status-start', 'later-status-asserted', 'server-stop-start', 'server-accept-loop-stopped',
    'factory-ready', 'https-server-start', 'https-server-started', 'acquire-start', 'acquire-completed',
    'admission-start', 'admission-completed', 'business-start-30000ms-operation-deadline', 'business-completed',
    'server-business-observed', 'server-business-not-observed', 'net-request-start', 'net-request-stop',
    'net-request-failed', 'net-connect-start', 'net-connect-stop', 'net-connect-failed', 'net-tls-start',
    'net-tls-stop', 'net-tls-failed', 'net-request-headers-start', 'net-request-headers-stop',
    'net-response-headers-start', 'net-response-headers-stop'
)
foreach ($fixture in @('broker', 'soap')) {
    $path = Join-Path $env:SIP_TIMEOUT_DIAGNOSTICS ($fixture + '.json')
    $observations[$fixture] = @()
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $rows = @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    if ($rows.Count -gt 256) { throw 'TIMEOUT_OBSERVATIONS_BOUND_EXCEEDED' }
    foreach ($row in $rows) {
        if ($phases -cnotcontains [string]$row.phase) { throw 'TIMEOUT_OBSERVATION_PHASE_INVALID' }
        $observations[$fixture] += [ordered]@{
            phase = [string]$row.phase
            utc = ([DateTimeOffset]$row.utc).ToString('O')
            elapsedMs = [double]$row.elapsedMs
            pid = [int]$row.pid
            cpuMs = [double]$row.cpuMs
            workingSetBytes = [long]$row.workingSetBytes
            privateBytes = [long]$row.privateBytes
            threadPoolThreads = [int]$row.threadPoolThreads
            pendingWorkItems = [long]$row.pendingWorkItems
        }
    }
}
New-Item -ItemType Directory -Path $env:SIP_TIMEOUT_DIAGNOSTICS -Force | Out-Null
[ordered]@{
    diagnosticSha = $env:CANDIDATE_COMMIT_SHA
    runtimeSourceSha = '5319d7d404b3c7b04f9810df87ff2757421e6a45'
    results = $results
    observations = $observations
    limitations = @('Broker server acceptance/deadline start have no existing observation hook.', 'Network events are limited to the inherited diagnostic execution context; missing events are not proof of absence.', 'Process samples describe the test process, not runner-wide resource pressure.')
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $env:SIP_TIMEOUT_DIAGNOSTICS 'reduced.json') -Encoding utf8
foreach ($name in $names) {
    if (@($results | Where-Object { $_.name -ceq $name }).Count -ne 1) { throw 'TIMEOUT_NAMED_RESULT_MISSING_OR_DUPLICATE' }
}
Write-Host 'TIMEOUT_REDUCED_RESULTS_EXPORTED'
