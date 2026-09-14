using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class PostgresIsolationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADMIN_AUDIT_EXPORT_store_pages_ties_isolates_tenants_and_observes_late_inserts_without_snapshot(bool postgres)
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (postgres && (string.IsNullOrWhiteSpace(adminConnection) || string.IsNullOrWhiteSpace(migrationConnection)))
            Assert.Skip("The dedicated PostgreSQL 18 gate must provide admin and migration connections.");
        if (postgres) await ApplyMigrationAsync();
        await using AdminPostgresDataSource? pool = postgres ? new(adminConnection!) : null;
        InMemoryGatewayRegistry memory = new();
        IAdminGatewayRegistry registry = postgres ? new PostgresGatewayRegistry(pool!.Value) : memory;
        IAdminDirectoryStore store = postgres ? new PostgresAdminDirectoryStore(pool!) : new InMemoryAdminDirectoryStore(memory);
        CancellationToken token = TestContext.Current.CancellationToken;
        Guid tenant = Guid.NewGuid(), other = Guid.NewGuid();
        DateTimeOffset from = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero), to = from.AddMinutes(10);
        GatewayAuditEvent Event(DateTimeOffset at, Guid tenantId) => new(Guid.NewGuid(), at, tenantId,
            "admin", "export-fixture", "tenant.update", "tenant", tenantId.ToString("D"), Guid.NewGuid(),
            "success", "BGW-ADMIN-ACTION", new Dictionary<string, string>());
        try
        {
            foreach (Guid id in new[] { tenant, other })
                await registry.AddTenantAsync(new(id, "export-" + id.ToString("N"), "Export fixture", TenantStatus.Active, from), token);
            GatewayAuditEvent[] initial = [Event(from.AddMinutes(5), tenant), Event(from.AddMinutes(3), tenant),
                Event(from.AddMinutes(3), tenant), Event(from, tenant)];
            foreach (GatewayAuditEvent value in initial.Append(Event(from.AddMinutes(4), other)).Append(Event(from.AddTicks(-10), tenant)))
                await registry.AppendAuditAsync(value, token);
            GatewayAuditEvent[] ordered = initial.OrderByDescending(value => value.OccurredAt).ThenByDescending(value => value.Id).ToArray();
            IReadOnlyList<GatewayAuditEvent> first = await store.ExportAuditAsync(tenant, from, to, null, null, 2, token);
            Assert.Equal(ordered.Take(2).Select(value => value.Id), first.Select(value => value.Id));
            GatewayAuditEvent behind = Event(from.AddMinutes(2), tenant);
            GatewayAuditEvent ahead = Event(from.AddMinutes(4), tenant);
            // Commits between page requests: only rows below the cursor remain reachable.
            await Task.WhenAll(new[] { behind, ahead, Event(to, tenant) }.Select(value => registry.AppendAuditAsync(value, token)));
            IReadOnlyList<GatewayAuditEvent> second = await store.ExportAuditAsync(tenant, from, to, first[^1].OccurredAt, first[^1].Id, 2, token);
            Assert.Equal(new[] { ordered[2].Id, behind.Id }, second.Select(value => value.Id));
            IReadOnlyList<GatewayAuditEvent> last = await store.ExportAuditAsync(tenant, from, to, second[^1].OccurredAt, second[^1].Id, 2, token);
            Assert.Equal(ordered[3].Id, Assert.Single(last).Id);
            Assert.Empty(await store.ExportAuditAsync(tenant, from, to, last[^1].OccurredAt, last[^1].Id, 2, token));
            Assert.Contains(await store.ExportAuditAsync(tenant, from, to, null, null, 1001, token), value => value.Id == ahead.Id);
            Assert.Single(await store.ExportAuditAsync(other, from, to, null, null, 2, token));
            Assert.Empty(await store.ExportAuditAsync(Guid.NewGuid(), from, to, null, null, 2, token));
            foreach ((DateTimeOffset start, DateTimeOffset end, DateTimeOffset? cursor, Guid? id, int limit) in new (DateTimeOffset, DateTimeOffset, DateTimeOffset?, Guid?, int)[]
            {
                (from, to, null, Guid.NewGuid(), 2), (from, to, from, null, 2),
                (from, to, from.ToOffset(TimeSpan.FromHours(1)), Guid.NewGuid(), 2),
                (from.ToOffset(TimeSpan.FromHours(1)), to, null, null, 2),
                (from, to.ToOffset(TimeSpan.FromHours(1)), null, null, 2),
                (to, from, null, null, 2), (from, from, null, null, 2),
                (from, to, null, null, 0), (from, to, null, null, 1002)
            })
            {
                GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => store.ExportAuditAsync(tenant, start, end, cursor, id, limit, token));
                Assert.Equal("BGW-ADMIN-AUDIT-EXPORT", failure.Code);
                Assert.Equal(400, failure.StatusCode);
            }
        }
        finally
        {
            if (postgres)
            {
                await ExecuteNonQueryAsync(migrationConnection!, "DELETE FROM gateway.audit_event WHERE tenant_id IN ($1,$2)", CancellationToken.None, tenant, other);
                await ExecuteNonQueryAsync(migrationConnection!, "DELETE FROM gateway.tenant WHERE id IN ($1,$2)", CancellationToken.None, tenant, other);
            }
        }
    }

    [Fact]
    public async Task P2_01_IT_PostgreSQL18_pre_authority_denials_persist_only_a_fixed_bounded_target()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the admin connection.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration connection.");

        await ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(adminConnection);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        TestClock clock = new(DateTimeOffset.UtcNow);
        string suffix = Guid.NewGuid().ToString("N");
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        string rawSentinel = "P2-01-RAW-⚠-/../\"'\r\n";
        string connectorSelector = "synthetic-" + rawSentinel + new string('λ', 300);
        string operationSelector = rawSentinel + new string('Ω', 300);

        try
        {
            await registry.AddTenantAsync(new(tenantId, "p201-t-" + suffix, "P2-01 tenant", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
            await registry.AddApplicationAsync(new(applicationId, "p201-a-" + suffix, "P2-01 application", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
            await registry.AddEnvironmentAsync(new(environmentId, "p201-e-" + suffix[..20], "P2-01 environment", false), TestContext.Current.CancellationToken);
            await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "1.0.0", clock.UtcNow), TestContext.Current.CancellationToken);

            RegisteredInstallationIdentity active = new(
                installationId, tenantId, applicationId, environmentId,
                TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3],
                clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "1.0.0", null);
            NeverRuntimeDependencies dependencies = new();
            RestrictedEgressService service = new(
                registry, new GatewayOperationCatalog([]), dependencies, dependencies, dependencies, dependencies, clock);
            (RegisteredInstallationIdentity Identity, string ExpectedCode)[] cases =
            [
                (active with { InstallationStatus = InstallationStatus.Revoked }, "BGW-INSTALLATION-REVOKED"),
                (active, "BGW-AUTHZ-OPERATION-DENIED")
            ];

            foreach ((RegisteredInstallationIdentity identity, string expectedCode) in cases)
            {
                Guid correlationId = Guid.NewGuid();
                GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => service.InvokeAsync(
                    new(identity, Guid.NewGuid()), connectorSelector, operationSelector,
                    new("1.0", new("application/json", "utf8", "{}"), correlationId),
                    TestContext.Current.CancellationToken));

                Assert.Equal(403, failure.StatusCode);
                Assert.Equal(expectedCode, failure.Code);
                Assert.Equal(expectedCode, failure.Message);
                await using NpgsqlConnection owner = new(migrationConnection);
                await owner.OpenAsync(TestContext.Current.CancellationToken);
                await using NpgsqlCommand audit = new("""
                    SELECT target_id, outcome, reason_code, metadata_redacted::text, row_to_json(a)::text
                      FROM gateway.audit_event AS a
                     WHERE correlation_id=$1
                    """, owner);
                audit.Parameters.AddWithValue(correlationId);
                await using NpgsqlDataReader reader = await audit.ExecuteReaderAsync(TestContext.Current.CancellationToken);
                Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
                string persisted = reader.GetString(4);
                Assert.Equal("unresolved-operation", reader.GetString(0));
                Assert.Equal("failure", reader.GetString(1));
                Assert.Equal(expectedCode, reader.GetString(2));
                Assert.True(reader.GetString(0).Length <= 256);
                Assert.DoesNotContain(rawSentinel, persisted, StringComparison.Ordinal);
                Assert.DoesNotContain(connectorSelector, persisted, StringComparison.Ordinal);
                Assert.DoesNotContain(operationSelector, persisted, StringComparison.Ordinal);
                Assert.False(await reader.ReadAsync(TestContext.Current.CancellationToken));
            }
            Assert.Equal(0, dependencies.Calls);
        }
        finally
        {
            await ExecuteNonQueryAsync(migrationConnection, "DELETE FROM gateway.audit_event WHERE tenant_id=$1", CancellationToken.None, tenantId);
            await ExecuteNonQueryAsync(migrationConnection, "DELETE FROM gateway.installation WHERE id=$1", CancellationToken.None, installationId);
            await ExecuteNonQueryAsync(migrationConnection, "DELETE FROM gateway.application WHERE id=$1", CancellationToken.None, applicationId);
            await ExecuteNonQueryAsync(migrationConnection, "DELETE FROM gateway.environment WHERE id=$1", CancellationToken.None, environmentId);
            await ExecuteNonQueryAsync(migrationConnection, "DELETE FROM gateway.tenant WHERE id=$1", CancellationToken.None, tenantId);
        }
    }

    [Fact]
    public async Task FSE2_DIAGNOSTICS_unknown_upstream_code_is_rejected_at_domain_and_storage_boundaries()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await ApplyMigrationAsync();
        (uint oid, string definition) first = await ReadDiagnosticCodeConstraintAsync(connectionString);
        await ApplyMigrationAsync();
        Assert.Equal(first, await ReadDiagnosticCodeConstraintAsync(connectionString));

        string[] rejected =
        [
            "FSE2_NOT_ALLOWLISTED", "Syntax", " syntax", "syntax ", "syntax/escape", "syntax\\escape", "syntax%0A"
        ];
        foreach (string value in rejected)
        {
            Assert.Throws<ArgumentException>(() => GatewayAuditFailureDiagnostics.Create(
                GatewayAuditFailurePhase.UpstreamHttpResponse,
                400,
                GatewayAuditStatusCategory.ClientError,
                value,
                null));
            await AssertDiagnosticCodeConstraintRejectsAsync(connectionString, value, local: false);
        }
    }

    [Fact]
    public async Task FSE2_DIAGNOSTICS_unknown_local_code_is_rejected_at_domain_and_storage_boundaries()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await ApplyMigrationAsync();
        string[] rejected =
        [
            "FSE2_NOT_ALLOWLISTED", "fse2_response_invalid", " FSE2_RESPONSE_INVALID",
            "FSE2_RESPONSE_INVALID ", "FSE2_RESPONSE_INVALID/escape", "FSE2_RESPONSE_INVALID%0A"
        ];
        foreach (string value in rejected)
        {
            Assert.Throws<ArgumentException>(() => GatewayAuditFailureDiagnostics.Create(
                GatewayAuditFailurePhase.LocalResponseMappingFailure,
                200,
                GatewayAuditStatusCategory.Success,
                null,
                value));
            await AssertDiagnosticCodeConstraintRejectsAsync(connectionString, value, local: true);
        }
    }

    [Fact]
    public async Task FSE2_DIAGNOSTICS_corrupt_or_non_allowlisted_persisted_code_is_not_exposed()
    {
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION")
            ?? migrationConnection;
        if (string.IsNullOrWhiteSpace(migrationConnection) || string.IsNullOrWhiteSpace(adminConnection))
            Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await ApplyMigrationAsync();
        Guid tenantId = Guid.NewGuid();
        Guid auditId = Guid.NewGuid();
        await using AdminPostgresDataSource adminPool = new(adminConnection);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        await registry.AddTenantAsync(new(
            tenantId,
            "corrupt-diag-" + tenantId.ToString("N"),
            "Corrupt diagnostics read-back",
            TenantStatus.Active,
            DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);

        await using NpgsqlConnection connection = new(migrationConnection);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        string constraintDefinition;
        await using (NpgsqlCommand definition = new(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='ck_audit_failure_diagnostic_codes_allowlisted' AND conrelid='gateway.audit_event'::regclass",
            connection))
            constraintDefinition = Assert.IsType<string>(await definition.ExecuteScalarAsync(TestContext.Current.CancellationToken));

        await using (NpgsqlTransaction transaction = await connection.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await using (NpgsqlCommand drop = new(
                "ALTER TABLE gateway.audit_event DROP CONSTRAINT ck_audit_failure_diagnostic_codes_allowlisted",
                connection,
                transaction))
                await drop.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            await using (NpgsqlCommand insert = new(
                "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted,failure_phase,upstream_status,status_category,safe_upstream_code,local_safe_code) VALUES($1,now(),$2,'installation','bounded-test','operation.invoke','operation','fse2/create',$3,'failure','BGW-EGRESS-UPSTREAM-REJECTED','{}'::jsonb,'UPSTREAM_HTTP_RESPONSE',400,'CLIENT_ERROR','FSE2_NOT_ALLOWLISTED',NULL)",
                connection,
                transaction))
            {
                insert.Parameters.AddWithValue(auditId);
                insert.Parameters.AddWithValue(tenantId);
                insert.Parameters.AddWithValue(Guid.NewGuid());
                await insert.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            }
            await using (NpgsqlCommand restore = new(
                $"ALTER TABLE gateway.audit_event ADD CONSTRAINT ck_audit_failure_diagnostic_codes_allowlisted {constraintDefinition} NOT VALID",
                connection,
                transaction))
                await restore.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        try
        {
            PostgresAdminDirectoryStore directory = new(adminPool);
            InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                directory.ListAuditAsync(tenantId, 0, 10, TestContext.Current.CancellationToken));
            Assert.Equal("Persisted audit failure diagnostics are invalid.", failure.Message);
            Assert.DoesNotContain("FSE2_NOT_ALLOWLISTED", failure.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            await using NpgsqlTransaction cleanup = await connection.BeginTransactionAsync(CancellationToken.None);
            await using (NpgsqlCommand deleteAudit = new(
                "DELETE FROM gateway.audit_event WHERE id=$1",
                connection,
                cleanup))
            {
                deleteAudit.Parameters.AddWithValue(auditId);
                await deleteAudit.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await using (NpgsqlCommand validate = new(
                "ALTER TABLE gateway.audit_event VALIDATE CONSTRAINT ck_audit_failure_diagnostic_codes_allowlisted",
                connection,
                cleanup))
                await validate.ExecuteNonQueryAsync(CancellationToken.None);
            await using (NpgsqlCommand deleteTenant = new(
                "DELETE FROM gateway.tenant WHERE id=$1",
                connection,
                cleanup))
            {
                deleteTenant.Parameters.AddWithValue(tenantId);
                await deleteTenant.ExecuteNonQueryAsync(CancellationToken.None);
            }
            await cleanup.CommitAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task FSE2_IT_DAT_PostgreSQL18_failure_diagnostics_round_trip()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the admin connection.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource pool = new(connectionString);
        PostgresGatewayRegistry registry = new(pool.Value);
        Guid tenantId = Guid.NewGuid();
        Guid correlationId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await registry.AddTenantAsync(new(tenantId, "diag-" + tenantId.ToString("N"), "Diagnostics", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await registry.AppendAuditAsync(new(
            Guid.NewGuid(), now, tenantId, "installation", Guid.NewGuid().ToString("D"),
            "operation.invoke", "operation", "fse2/create", correlationId, "failure",
            "BGW-EGRESS-UPSTREAM-REJECTED", new Dictionary<string, string>
            {
                ["connectorVersion"] = "1.0.0",
                ["callerKind"] = "Direct"
            },
            GatewayAuditFailureDiagnostics.Create(
                GatewayAuditFailurePhase.LocalResponseMappingFailure,
                200,
                GatewayAuditStatusCategory.Success,
                null,
                "FSE2_RESPONSE_INVALID")), TestContext.Current.CancellationToken);

        PostgresAdminDirectoryStore directory = new(pool);
        GatewayAuditEvent read = Assert.Single((await directory.ListAuditAsync(
            tenantId, 0, 10, TestContext.Current.CancellationToken)).Items,
            value => value.CorrelationId == correlationId);
        GatewayAuditFailureDiagnostics diagnostics = Assert.IsType<GatewayAuditFailureDiagnostics>(read.FailureDiagnostics);
        Assert.Equal(GatewayAuditFailurePhase.LocalResponseMappingFailure, diagnostics.FailurePhase);
        Assert.Equal(200, diagnostics.UpstreamStatus);
        Assert.Equal(GatewayAuditStatusCategory.Success, diagnostics.StatusCategory);
        Assert.Null(diagnostics.SafeUpstreamCode);
        Assert.Equal("FSE2_RESPONSE_INVALID", diagnostics.LocalSafeCode);
        Assert.DoesNotContain(read.Metadata.Keys, key => key.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("upstream", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource pool = new(connectionString);
        PostgresGatewayRegistry registry = new(pool.Value);
        DateTimeOffset now = DateTimeOffset.UtcNow; Guid tenantId = Guid.NewGuid();

        await registry.AddTenantWithAuditAsync(new(tenantId, "rls-" + tenantId.ToString("N"), "Created", TenantStatus.Active, now), Audit(tenantId, Guid.NewGuid(), "tenant.create", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        TenantRecord updated = await registry.UpdateTenantWithAuditAsync(tenantId, "Updated", 1, Audit(tenantId, Guid.NewGuid(), "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        TenantRecord disabled = await registry.DisableTenantWithAuditAsync(tenantId, updated.RowVersion, Audit(tenantId, Guid.NewGuid(), "tenant.disable", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        Assert.Equal(3, disabled.RowVersion); Assert.Equal(TenantStatus.Suspended, disabled.Status);
        PostgresAdminDirectoryStore directory = new(pool);
        Assert.Equal(3, (await directory.ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken)).Total);

        await using (NpgsqlConnection connection = await pool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken))
        {
            await using NpgsqlCommand role = new("SELECT r.rolsuper,r.rolbypassrls,c.relforcerowsecurity FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE r.rolname=current_user AND n.nspname='gateway' AND c.relname='audit_event'", connection);
            await using NpgsqlDataReader reader = await role.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken)); Assert.False(reader.GetBoolean(0)); Assert.False(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2));
        }
        await using (NpgsqlConnection connection = await pool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken))
        await using (NpgsqlCommand context = new("SELECT current_setting('app.tenant_id',true)", connection))
            Assert.True(string.IsNullOrEmpty(await context.ExecuteScalarAsync(TestContext.Current.CancellationToken) as string));

        long expected = disabled.RowVersion;
        TaskCompletionSource barrier = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<TenantRecord> Race(string name)
        {
            await barrier.Task.WaitAsync(TestContext.Current.CancellationToken);
            return await registry.UpdateTenantWithAuditAsync(tenantId, name, expected, Audit(tenantId, Guid.NewGuid(), "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
        }
        Task<TenantRecord> first = Race("Concurrent A"); Task<TenantRecord> second = Race("Concurrent B"); barrier.SetResult();
        Exception? firstError = await Record.ExceptionAsync(() => first); Exception? secondError = await Record.ExceptionAsync(() => second);
        Assert.True((firstError is null) ^ (secondError is null));
        GatewayException conflict = Assert.IsType<GatewayException>(firstError ?? secondError); Assert.Equal("BGW-CONCURRENCY-CONFLICT", conflict.Code);
        Assert.Equal(4, (await directory.ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken)).Total);

        Guid applicationId = Guid.NewGuid();
        await registry.AddApplicationWithAuditAsync(new(applicationId, "rls-app-" + applicationId.ToString("N"), "Created", ApplicationStatus.Active, "3.0.0", null, now),
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.create", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        ApplicationRecord application = await registry.UpdateApplicationWithAuditAsync(applicationId, "Updated", "3.1.0", null, 1,
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.update", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        application = await registry.DisableApplicationWithAuditAsync(applicationId, application.RowVersion,
            new(Guid.NewGuid(), now, null, "administrator", "test", "application.disable", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        long applicationExpected = application.RowVersion; TaskCompletionSource applicationBarrier = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<ApplicationRecord> RaceApplication(string name)
        {
            await applicationBarrier.Task.WaitAsync(TestContext.Current.CancellationToken);
            return await registry.UpdateApplicationWithAuditAsync(applicationId, name, "3.2.0", null, applicationExpected,
                new(Guid.NewGuid(), now, null, "administrator", "test", "application.update", "application", applicationId.ToString("D"), Guid.NewGuid(), "success", "BGW-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        }
        Task<ApplicationRecord> appFirst = RaceApplication("Concurrent A"); Task<ApplicationRecord> appSecond = RaceApplication("Concurrent B"); applicationBarrier.SetResult();
        Exception? appFirstError = await Record.ExceptionAsync(() => appFirst); Exception? appSecondError = await Record.ExceptionAsync(() => appSecond);
        Assert.True((appFirstError is null) ^ (appSecondError is null)); Assert.Equal("BGW-CONCURRENCY-CONFLICT", Assert.IsType<GatewayException>(appFirstError ?? appSecondError).Code);
        Assert.Equal(4L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.audit_event WHERE target_id=$1 AND action LIKE 'application.%'", applicationId.ToString("D")));
    }

    [Fact]
    public async Task IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL migration/admin connection is not configured; the dedicated PostgreSQL gate must provide it.");

        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("18.", connection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
        await ApplyMigrationAsync();

        Guid tenantA = Guid.NewGuid();
        Guid tenantB = Guid.NewGuid();
        Guid application = Guid.NewGuid();
        Guid environment = Guid.NewGuid();
        Guid installationA = Guid.NewGuid();
        Guid installationB = Guid.NewGuid();
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, TestContext.Current.CancellationToken);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,'A','active',now()),($3,$4,'B','active',now())", tenantA, "ta-" + tenantA.ToString("N"), tenantB, "tb-" + tenantB.ToString("N"));
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,'App','active','1.0.0',now())", application, "app-" + application.ToString("N"));
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,'Test',false)", environment, "t-" + environment.ToString("N")[..20]);
        await ExecuteAsync(connection, transaction, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,created_at) VALUES($1,$2,$3,$4,'pending',now()),($5,$6,$3,$4,'pending',now())", installationA, tenantA, application, environment, installationB, tenantB);
        await ExecuteAsync(connection, transaction, "SET LOCAL ROLE gateway_runtime");
        await ExecuteAsync(connection, transaction, "SELECT set_config('app.tenant_id',$1,true)", tenantA.ToString("D"));
        await using NpgsqlCommand visible = new("SELECT id FROM gateway.installation ORDER BY id", connection, transaction);
        await using NpgsqlDataReader reader = await visible.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        List<Guid> ids = [];
        while (await reader.ReadAsync(TestContext.Current.CancellationToken)) ids.Add(reader.GetGuid(0));
        await reader.CloseAsync();
        Assert.Equal([installationA], ids);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using NpgsqlDataSource adminDataSource = NpgsqlDataSource.Create(connectionString);
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        string runtimeRole = "gateway_test_" + Guid.NewGuid().ToString("N");
        string runtimePassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        await using (NpgsqlConnection migrationConnection = new(migrationConnectionString))
        {
            await migrationConnection.OpenAsync(TestContext.Current.CancellationToken);
            Assert.StartsWith("18.", migrationConnection.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
            await ApplyMigrationAsync(migrationConnection);
            await using NpgsqlCommand createRole = new($"CREATE ROLE {runtimeRole} LOGIN PASSWORD '{runtimePassword}'; GRANT gateway_runtime TO {runtimeRole}", migrationConnection);
            await createRole.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        NpgsqlConnectionStringBuilder runtimeConnection = new(connectionString) { Username = runtimeRole, Password = runtimePassword };
        await using NpgsqlDataSource runtimeDataSource = NpgsqlDataSource.Create(runtimeConnection.ConnectionString);
        PostgresGatewayRegistry adminRegistry = new(adminDataSource);
        PostgresGatewayRegistry registry = new(runtimeDataSource);
        TestClock clock = new(DateTimeOffset.UtcNow);
        byte[] activationKey = SHA256.HashData("postgres-integration-activation"u8);
        EnrollmentSecurityOptions security = new() { ActivationHmacKey = activationKey };
        GatewayProvisioningService provisioningService = new(adminRegistry, clock, security);
        InstallationEnrollmentService enrollmentService = new(registry, new InMemoryEnrollmentChallengeStore(), clock, security);
        Guid suffix = Guid.NewGuid();
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        ProvisionedActivation provisioning = await provisioningService.CreateInstallationAsync(
            new(tenantId, "tenant-" + suffix.ToString("N"), "Tenant", TenantStatus.Active, clock.UtcNow),
            new(applicationId, "app-" + suffix.ToString("N"), "Application", ApplicationStatus.Active, "1.0.0", "2.0.0", clock.UtcNow),
            new(environmentId, "e-" + suffix.ToString("N")[..20], "Test", false), installationId, "integration-test", TestContext.Current.CancellationToken);

        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest certificateRequest = new("CN=postgres-integration", key, HashAlgorithmName.SHA256);
        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        EnrollmentChallengeResponse challenge = await enrollmentService.CreateChallengeAsync(new(provisioning.ActivationCodeId, Convert.ToBase64String(spki)), TestContext.Current.CancellationToken);
        EnrollmentChallenge proofChallenge = new(challenge.ChallengeId, provisioning.ActivationCodeId, Base64Url.Decode(challenge.Challenge), spki, challenge.ExpiresAt);
        byte[] proofSignature = key.SignData(InstallationEnrollmentService.BuildActivationProof(proofChallenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        EnrollmentResult result = await enrollmentService.ActivateAsync(new(challenge.ChallengeId, provisioning.ActivationCode, Convert.ToBase64String(certificate.RawData), Base64Url.Encode(proofSignature), "1.5.0"), TestContext.Current.CancellationToken);
        Assert.Equal(tenantId, result.TenantId);

        RegisteredInstallationIdentity identity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(certificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Credential lookup failed.");
        Assert.Equal(tenantId, identity.TenantId);

        clock.UtcNow = clock.UtcNow.AddDays(61);
        using ECDsa replacementKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest replacementRequest = new("CN=postgres-integration-renewed", replacementKey, HashAlgorithmName.SHA256);
        replacementRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        replacementRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 replacementCertificate = replacementRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] replacementSpki = replacementKey.ExportSubjectPublicKeyInfo();
        byte[] renewalProof = InstallationEnrollmentService.BuildRenewalProof(installationId, identity.CredentialId, SHA256.HashData(replacementSpki));
        byte[] renewalSignature = replacementKey.SignData(renewalProof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await enrollmentService.RenewAsync(identity, new(Convert.ToBase64String(replacementCertificate.RawData), Base64Url.Encode(renewalSignature)), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity replacementIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(replacementCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Replacement credential lookup failed.");
        Assert.Equal(CredentialStatus.Active, replacementIdentity.CredentialStatus);
        RegisteredInstallationIdentity overlapIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(certificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Overlap credential lookup failed.");
        Assert.Equal(CredentialStatus.Overlap, overlapIdentity.CredentialStatus);
        await adminRegistry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, "vendor", "send", true, clock.UtcNow), TestContext.Current.CancellationToken);
        Assert.True(await registry.IsGrantedAsync(installationId, tenantId, "vendor", "send", clock.UtcNow, TestContext.Current.CancellationToken));
        byte[] nonceHash = SHA256.HashData("nonce"u8);
        Assert.True(await registry.TryStoreNonceAsync(installationId, nonceHash, clock.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.False(await registry.TryStoreNonceAsync(installationId, nonceHash, clock.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.True(await adminRegistry.RevokeInstallationAsync(installationId, "integration test", clock.UtcNow, TestContext.Current.CancellationToken));
        RegisteredInstallationIdentity revoked = await registry.FindIdentityByCertificateAsync(SHA256.HashData(replacementCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Revoked credential lookup failed.");
        Assert.Equal(InstallationStatus.Revoked, revoked.InstallationStatus);
        Assert.Equal(CredentialStatus.Revoked, revoked.CredentialStatus);

        Guid directInstallationId = Guid.NewGuid();
        GatewayAuditEvent directCreateAudit = new(Guid.NewGuid(), clock.UtcNow, tenantId, "administrator", "postgres-test", "installation.create", "installation", directInstallationId.ToString("D"), Guid.NewGuid(), "success", "BGW-INSTALLATION-CREATED", new Dictionary<string, string> { ["installationKind"] = InstallationKind.Direct.ToString() });
        ProvisionedActivation directProvisioning = await provisioningService.CreateAdminInstallationAsync(
            new(directInstallationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, clock.UtcNow, InstallationKind: InstallationKind.Direct, UpdatedAt: clock.UtcNow),
            "postgres-test", directCreateAudit, TestContext.Current.CancellationToken);
        using ECDsa directKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest directCertificateRequest = new("CN=postgres-direct-integration", directKey, HashAlgorithmName.SHA256);
        directCertificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
        directCertificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 directCertificate = directCertificateRequest.CreateSelfSigned(clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddDays(90));
        byte[] directSpki = directKey.ExportSubjectPublicKeyInfo();
        EnrollmentChallengeResponse directChallenge = await enrollmentService.CreateChallengeAsync(new(directProvisioning.ActivationCodeId, Convert.ToBase64String(directSpki)), TestContext.Current.CancellationToken);
        EnrollmentChallenge directProofChallenge = new(directChallenge.ChallengeId, directProvisioning.ActivationCodeId, Base64Url.Decode(directChallenge.Challenge), directSpki, directChallenge.ExpiresAt);
        byte[] directProof = directKey.SignData(InstallationEnrollmentService.BuildActivationProof(directProofChallenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        await enrollmentService.ActivateAsync(new(directChallenge.ChallengeId, directProvisioning.ActivationCode, Convert.ToBase64String(directCertificate.RawData), Base64Url.Encode(directProof), ClientVersion: "1.0.0"), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity directIdentity = await registry.FindIdentityByCertificateAsync(SHA256.HashData(directCertificate.RawData), TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Direct credential lookup failed.");
        Assert.Equal(InstallationKind.Direct, directIdentity.InstallationKind);
        Assert.Equal("1.0.0", directIdentity.ClientVersion);
        Assert.Equal(identity.TenantId, directIdentity.TenantId);
        Assert.Equal(identity.ApplicationId, directIdentity.ApplicationId);
        await adminRegistry.AddGrantAsync(new(Guid.NewGuid(), directInstallationId, tenantId, "vendor", "send", true, clock.UtcNow), TestContext.Current.CancellationToken);
        Assert.True(await registry.IsGrantedAsync(directInstallationId, tenantId, "vendor", "send", clock.UtcNow, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void IT_DAT_Migration_forces_RLS_and_contains_no_secret_value_columns()
    {
        string sql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0001_gateway_m2.sql"));
        Assert.Contains("ALTER TABLE gateway.installation FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("ALTER TABLE gateway.installation_credential FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("ALTER TABLE gateway.activation_code FORCE ROW LEVEL SECURITY", sql, StringComparison.Ordinal);
        Assert.Contains("metadata_redacted jsonb", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("secret_value", sql, StringComparison.OrdinalIgnoreCase);
        string connectorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0002_connector_configuration_m4.sql"));
        Assert.Contains("connector_version_immutable", connectorSql, StringComparison.Ordinal);
        Assert.Contains("state IN ('draft','validated','published','superseded','retired')", connectorSql, StringComparison.Ordinal);
        Assert.DoesNotContain("secret_value", connectorSql, StringComparison.OrdinalIgnoreCase);
        string roleRevocationSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0006_admin_role_revocation_m5.sql"));
        Assert.Contains("GRANT DELETE ON gateway.admin_role_assignment TO gateway_admin", roleRevocationSql, StringComparison.Ordinal);
        Assert.DoesNotContain("gateway_runtime", roleRevocationSql, StringComparison.Ordinal);
        string bindingImmutabilitySql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0007_binding_bundle_immutability_m5.sql"));
        Assert.Contains("GRANT UPDATE (state)", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.Contains("connector binding revisions are immutable", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.Contains("binding activation requires a current four-eyes approval", bindingImmutabilitySql, StringComparison.Ordinal);
        Assert.DoesNotContain("GRANT UPDATE ON gateway.connector_binding_bundle_version", bindingImmutabilitySql, StringComparison.Ordinal);
        string locatorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0009_runtime_locator_resolution_m5.sql"));
        Assert.Contains("SECURITY DEFINER", locatorSql, StringComparison.Ordinal);
        Assert.Contains("SET search_path = pg_catalog, gateway", locatorSql, StringComparison.Ordinal);
        Assert.Contains("OWNER TO gateway_locator_owner", locatorSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE CREATE ON SCHEMA gateway FROM gateway_locator_owner", locatorSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE ALL ON gateway.provider_resource_locator FROM PUBLIC, gateway_runtime", locatorSql, StringComparison.Ordinal);
        Assert.DoesNotContain("dynamic SQL", locatorSql, StringComparison.OrdinalIgnoreCase);
        string operationLocatorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0010_operation_scoped_locator_m5.sql"));
        Assert.Contains("p_logical_binding_id", operationLocatorSql, StringComparison.Ordinal);
        Assert.Contains("resource.key = p_logical_binding_id", operationLocatorSql, StringComparison.Ordinal);
        Assert.Contains("operation -> 'authentication'", operationLocatorSql, StringComparison.Ordinal);
        string directInstallationSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0011_direct_installation_m55.sql"));
        Assert.Contains("installation_kind IN ('broker','direct')", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("installation_kind = 'direct' AND broker_version IS NULL", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("CREATE OR REPLACE FUNCTION gateway.resolve_installation_client_metadata", directInstallationSql, StringComparison.Ordinal);
        Assert.Contains("REVOKE ALL ON FUNCTION gateway.resolve_installation_client_metadata(bytea) FROM PUBLIC", directInstallationSql, StringComparison.Ordinal);
        Assert.DoesNotContain("DROP FUNCTION", directInstallationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BYPASSRLS", directInstallationSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret_value", directInstallationSql, StringComparison.OrdinalIgnoreCase);
        string typedComposedLocatorSql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0014_typed_composed_soap_request_inputs.sql"));
        Assert.Contains("typedComposedSoapRequest' -> 'serverOwnedInputs'", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.Contains("installation_connector_grant", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.Contains("SECURITY DEFINER", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.Contains("OWNER TO gateway_locator_owner", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.Contains("TO gateway_runtime", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.Contains("FROM PUBLIC, gateway_admin, gateway_readonly", typedComposedLocatorSql, StringComparison.Ordinal);
        Assert.DoesNotContain("GRANT SELECT", typedComposedLocatorSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DROP FUNCTION", typedComposedLocatorSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BYPASSRLS", typedComposedLocatorSql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret_value", typedComposedLocatorSql, StringComparison.OrdinalIgnoreCase);
        string appendOnlySql = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0017_event_tables_append_only.sql"));
        Assert.Contains("REVOKE UPDATE, DELETE, TRUNCATE ON TABLE gateway.audit_event FROM gateway_admin", appendOnlySql, StringComparison.Ordinal);
        Assert.Contains("REVOKE ALL PRIVILEGES ON TABLE gateway.invocation_event FROM gateway_admin", appendOnlySql, StringComparison.Ordinal);
        Assert.DoesNotContain("CREATE TRIGGER", appendOnlySql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\nGRANT ", appendOnlySql, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SEC_DAT_PostgreSQL18_event_table_privilege_matrix_is_minimal_and_append_only_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("18.", owner.PostgreSqlVersion.ToString(), StringComparison.Ordinal);
        await ApplyMigrationAsync(owner);

        string[] privileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"];
        foreach (string privilege in privileges)
        {
            Assert.Equal(privilege is "SELECT" or "INSERT", await HasTablePrivilegeAsync(owner, "gateway_admin", "gateway.audit_event", privilege));
            Assert.False(await HasTablePrivilegeAsync(owner, "gateway_admin", "gateway.invocation_event", privilege));
            Assert.Equal(privilege == "INSERT", await HasTablePrivilegeAsync(owner, "gateway_runtime", "gateway.audit_event", privilege));
            Assert.Equal(privilege == "INSERT", await HasTablePrivilegeAsync(owner, "gateway_runtime", "gateway.invocation_event", privilege));
            Assert.False(await HasTablePrivilegeAsync(owner, "gateway_readonly", "gateway.audit_event", privilege));
            Assert.False(await HasTablePrivilegeAsync(owner, "gateway_readonly", "gateway.invocation_event", privilege));
        }
    }

    [Fact]
    public async Task SEC_DAT_PostgreSQL18_gateway_admin_can_append_and_read_audit_but_cannot_mutate_event_rows_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);
        EventPrivilegeFixture fixture = await CreateEventPrivilegeFixtureAsync(owner);
        Guid appendedAuditId = Guid.NewGuid();
        try
        {
            await ExecuteAsRoleAsync(
                owner,
                "gateway_admin",
                fixture.TenantA,
                "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'administrator','append-only-test','security.append-only','audit_event',$3,$4,'success','ADMIN-APPEND','{}'::jsonb)",
                appendedAuditId,
                fixture.TenantA,
                fixture.Marker,
                Guid.NewGuid());
            Assert.Equal(
                "ADMIN-APPEND",
                await ScalarAsRoleAsync<string>(owner, "gateway_admin", fixture.TenantA, "SELECT reason_code FROM gateway.audit_event WHERE id=$1", appendedAuditId));

            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "UPDATE gateway.audit_event SET reason_code='MUTATED' WHERE id=$1", fixture.AuditId);
            await AssertEventRowsUnchangedAsync(owner, fixture);
            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "DELETE FROM gateway.audit_event WHERE id=$1", fixture.AuditId);
            await AssertEventRowsUnchangedAsync(owner, fixture);
            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "TRUNCATE TABLE gateway.audit_event");
            await AssertEventRowsUnchangedAsync(owner, fixture);

            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "UPDATE gateway.invocation_event SET outcome='failure' WHERE id=$1", fixture.InvocationId);
            await AssertEventRowsUnchangedAsync(owner, fixture);
            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "DELETE FROM gateway.invocation_event WHERE id=$1", fixture.InvocationId);
            await AssertEventRowsUnchangedAsync(owner, fixture);
            await AssertRoleDeniedAsync(owner, "gateway_admin", fixture.TenantA, "TRUNCATE TABLE gateway.invocation_event");
            await AssertEventRowsUnchangedAsync(owner, fixture);
        }
        finally
        {
            await CleanupEventPrivilegeFixtureAsync(owner, fixture);
        }
    }

    [Fact]
    public async Task SEC_DAT_PostgreSQL18_gateway_runtime_can_append_but_cannot_read_or_mutate_event_rows_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);
        EventPrivilegeFixture fixture = await CreateEventPrivilegeFixtureAsync(owner);
        Guid auditId = Guid.NewGuid();
        Guid invocationId = Guid.NewGuid();
        try
        {
            await ExecuteAsRoleAsync(
                owner,
                "gateway_runtime",
                fixture.TenantA,
                "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'installation','append-only-test','security.append-only','audit_event',$3,$4,'success','RUNTIME-APPEND','{}'::jsonb)",
                auditId,
                fixture.TenantA,
                fixture.Marker,
                Guid.NewGuid());
            await ExecuteAsRoleAsync(
                owner,
                "gateway_runtime",
                fixture.TenantA,
                "INSERT INTO gateway.invocation_event(id,occurred_at,tenant_id,installation_id,connector_id,operation_id,correlation_id,outcome,duration_ms,payload_bytes) VALUES($1,now(),$2,$3,$4,$5,$6,'success',1,0)",
                invocationId,
                fixture.TenantA,
                fixture.InstallationA,
                fixture.ConnectorId,
                fixture.Marker,
                Guid.NewGuid());
            Assert.Equal(1L, await ScalarOwnerAsync<long>(owner, "SELECT count(*) FROM gateway.audit_event WHERE id=$1", auditId));
            Assert.Equal(1L, await ScalarOwnerAsync<long>(owner, "SELECT count(*) FROM gateway.invocation_event WHERE id=$1", invocationId));

            foreach ((string table, Guid id) in new[] { ("audit_event", auditId), ("invocation_event", invocationId) })
            {
                await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture.TenantA, $"SELECT id FROM gateway.{table} WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture.TenantA, $"UPDATE gateway.{table} SET outcome='failure' WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture.TenantA, $"DELETE FROM gateway.{table} WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_runtime", fixture.TenantA, $"TRUNCATE TABLE gateway.{table}");
            }
            Assert.Equal("success", await ScalarOwnerAsync<string>(owner, "SELECT outcome FROM gateway.audit_event WHERE id=$1", auditId));
            Assert.Equal("success", await ScalarOwnerAsync<string>(owner, "SELECT outcome FROM gateway.invocation_event WHERE id=$1", invocationId));
        }
        finally
        {
            await CleanupEventPrivilegeFixtureAsync(owner, fixture);
        }
    }

    [Fact]
    public async Task SEC_DAT_PostgreSQL18_gateway_readonly_cannot_read_or_mutate_event_rows_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);
        EventPrivilegeFixture fixture = await CreateEventPrivilegeFixtureAsync(owner);
        try
        {
            foreach ((string table, Guid id) in new[] { ("audit_event", fixture.AuditId), ("invocation_event", fixture.InvocationId) })
            {
                await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture.TenantA, $"SELECT id FROM gateway.{table} WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture.TenantA, $"INSERT INTO gateway.{table} SELECT * FROM gateway.{table} WHERE false");
                await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture.TenantA, $"UPDATE gateway.{table} SET outcome='failure' WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture.TenantA, $"DELETE FROM gateway.{table} WHERE id=$1", id);
                await AssertRoleDeniedAsync(owner, "gateway_readonly", fixture.TenantA, $"TRUNCATE TABLE gateway.{table}");
            }
            await AssertEventRowsUnchangedAsync(owner, fixture);
        }
        finally
        {
            await CleanupEventPrivilegeFixtureAsync(owner, fixture);
        }
    }

    [Fact]
    public async Task SEC_DAT_PostgreSQL18_event_RLS_preserves_tenant_isolation_and_global_audit_semantics_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("The dedicated PostgreSQL 18 gate must provide the migration/admin connection.");

        await using NpgsqlConnection owner = new(connectionString);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);
        EventPrivilegeFixture fixture = await CreateEventPrivilegeFixtureAsync(owner);
        try
        {
            await ExecuteOwnerAsync(owner, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'administrator','append-only-test','security.append-only','audit_event',$3,$4,'success','TENANT-B','{}'::jsonb),($5,now(),NULL,'administrator','append-only-test','security.append-only','audit_event',$3,$6,'success','GLOBAL','{}'::jsonb)", Guid.NewGuid(), fixture.TenantB, fixture.Marker, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());

            Assert.Equal(2L, await ScalarAsRoleAsync<long>(owner, "gateway_admin", fixture.TenantA, "SELECT count(*) FROM gateway.audit_event WHERE target_id=$1", fixture.Marker));
            await AssertRlsDeniedAsync(owner, "gateway_admin", fixture.TenantA, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'administrator','append-only-test','security.append-only','audit_event',$3,$4,'success','CROSS-TENANT','{}'::jsonb)", Guid.NewGuid(), fixture.TenantB, fixture.Marker, Guid.NewGuid());
            await AssertRlsDeniedAsync(owner, "gateway_runtime", fixture.TenantA, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'installation','append-only-test','security.append-only','audit_event',$3,$4,'success','CROSS-TENANT','{}'::jsonb)", Guid.NewGuid(), fixture.TenantB, fixture.Marker, Guid.NewGuid());
            await AssertRlsDeniedAsync(owner, "gateway_runtime", fixture.TenantA, "INSERT INTO gateway.invocation_event(id,occurred_at,tenant_id,installation_id,connector_id,operation_id,correlation_id,outcome,duration_ms,payload_bytes) VALUES($1,now(),$2,$3,$4,$5,$6,'success',1,0)", Guid.NewGuid(), fixture.TenantB, fixture.InstallationB, fixture.ConnectorId, fixture.Marker, Guid.NewGuid());

            await ExecuteAsRoleAsync(owner, "gateway_admin", fixture.TenantA, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),NULL,'administrator','append-only-test','security.append-only','audit_event',$2,$3,'success','ADMIN-GLOBAL','{}'::jsonb)", Guid.NewGuid(), fixture.Marker, Guid.NewGuid());
            await ExecuteAsRoleAsync(owner, "gateway_runtime", fixture.TenantA, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),NULL,'installation','append-only-test','security.append-only','audit_event',$2,$3,'success','RUNTIME-GLOBAL','{}'::jsonb)", Guid.NewGuid(), fixture.Marker, Guid.NewGuid());
            Assert.Equal(5L, await ScalarOwnerAsync<long>(owner, "SELECT count(*) FROM gateway.audit_event WHERE target_id=$1", fixture.Marker));
        }
        finally
        {
            await CleanupEventPrivilegeFixtureAsync(owner, fixture);
        }
    }

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_runtime_locator_is_exactly_granted_and_not_enumerable_when_configured()
    {
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using NpgsqlConnection owner = new(migrationConnection);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(owner);

        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid(); Guid connectorId = Guid.NewGuid(); Guid versionId = Guid.NewGuid();
        Guid bindingId = Guid.NewGuid(); Guid catalogId = Guid.NewGuid();
        string suffix = Guid.NewGuid().ToString("N"); string slug = "locator-" + suffix;
        string resourceLogicalId = "api-key-" + suffix;
        byte[] catalogChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("catalog-" + suffix));
        byte[] bindingChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("binding-" + suffix));
        byte[] definitionChecksum = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("definition-" + suffix));
        Guid requesterId = Guid.NewGuid(); Guid approverId = Guid.NewGuid();
        ProviderResourceBinding resource = new("synthetic", "Synthetic", "synthetic", resourceLogicalId, ProviderResourceType.Secret, "API key", environmentId, slug, "submit", null, 1, null, null, Convert.ToHexString(catalogChecksum));
        string secretJson = JsonSerializer.Serialize(new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-api-key"] = resource });

        await using (NpgsqlTransaction setup = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,$3,'active',now())", tenantId, "t-" + suffix, "Locator tenant");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,$3,'active','3.0.0',now())", applicationId, "a-" + suffix, "Locator app");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,$3,false)", environmentId, "e-" + suffix[..20], "Locator env");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_definition(id,slug,display_name,status,created_at,created_by) VALUES($1,$2,$3,'active',now(),'test')", connectorId, slug, "Locator connector");
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_version(id,connector_id,version,schema_version,state,configuration_json,checksum_sha256,created_by,created_at,published_at) VALUES($1,$2,'1.0.0','1.0','published',$3::jsonb,$4,'test',now(),now())", versionId, connectorId, "{\"operations\":[{\"operationId\":\"submit\",\"authentication\":{\"kind\":\"apiKey\",\"secretBinding\":\"sample-vendor-api-key\"}},{\"operationId\":\"other-operation\",\"authentication\":{\"kind\":\"apiKey\",\"secretBinding\":\"other-operation-secret\"}}]}", definitionChecksum);
            await ExecuteAsync(owner, setup, "UPDATE gateway.connector_definition SET active_version_id=$2 WHERE id=$1", connectorId, versionId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.provider_resource_catalog_version(id,provider_id,provider_display_name,provider_type,resource_id,resource_type,display_name,environment_id,connector_scope,operation_scope,status,revision,checksum_sha256,created_at) VALUES($1,'synthetic','Synthetic','synthetic',$2,'secret','API key',$3,$4,'*','active',1,$5,now())", catalogId, resourceLogicalId, environmentId, slug, catalogChecksum);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.provider_resource_locator(provider_resource_catalog_id,provider_reference) VALUES($1,$2)", catalogId, "synthetic://controlled-" + suffix);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_binding_bundle_version(id,connector_id,connector_version_id,environment_id,revision,state,endpoints_json,secret_references_json,certificate_references_json,checksum_sha256,created_at,created_by) VALUES($1,$2,$3,$4,1,'draft','{}'::jsonb,$5::jsonb,'{}'::jsonb,$6,now(),'test')", bindingId, connectorId, versionId, environmentId, secretJson, bindingChecksum);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.admin_principal(id,issuer,subject,display_name,created_at,last_login_at) VALUES($1,'https://locator.invalid',$2,'Requester',now(),now()),($3,'https://locator.invalid',$4,'Approver',now(),now())", requesterId, "requester-" + suffix, approverId, "approver-" + suffix);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.connector_approval(id,connector_version_id,checksum_sha256,binding_digest_sha256,requested_by,approved_by,status,requested_at,approved_at) VALUES($1,$2,$3,$4,$5,$6,'approved',now(),now())", Guid.NewGuid(), versionId, definitionChecksum, bindingChecksum, requesterId, approverId);
            await ExecuteAsync(owner, setup, "UPDATE gateway.connector_binding_bundle_version SET state='active' WHERE id=$1", bindingId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,broker_version,created_at) VALUES($1,$2,$3,$4,'active','3.0.0',now())", installationId, tenantId, applicationId, environmentId);
            await ExecuteAsync(owner, setup, "INSERT INTO gateway.installation_connector_grant(id,installation_id,tenant_id,connector_id,operation_id,enabled,valid_from) VALUES($1,$2,$3,$4,'submit',true,now()-interval '1 minute')", Guid.NewGuid(), installationId, tenantId, connectorId);
            await setup.CommitAsync(TestContext.Current.CancellationToken);
        }

        await using (NpgsqlTransaction denied = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await ExecuteAsync(owner, denied, "SET LOCAL ROLE gateway_runtime");
            PostgresException direct = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(owner, denied, "SELECT provider_reference FROM gateway.provider_resource_locator"));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, direct.SqlState);
            await denied.RollbackAsync(TestContext.Current.CancellationToken);
        }

        async Task<string?> ResolveAsync(string operation, string logicalBindingId, Guid environment, Guid resourceId, long revision = 1)
        {
            await using NpgsqlTransaction runtime = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await ExecuteAsync(owner, runtime, "SET LOCAL ROLE gateway_runtime");
            await using NpgsqlCommand command = new("SELECT gateway.resolve_published_provider_locator($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", owner, runtime);
            foreach (object value in new object[] { resourceId, slug, operation, logicalBindingId, environment, bindingId, revision, bindingChecksum, installationId, tenantId, applicationId }) command.Parameters.AddWithValue(value);
            object? result = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
            await runtime.RollbackAsync(TestContext.Current.CancellationToken);
            return result is DBNull or null ? null : (string)result;
        }

        Assert.Equal("synthetic://controlled-" + suffix, await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId));
        Assert.Null(await ResolveAsync("other-operation", "sample-vendor-api-key", environmentId, catalogId));
        Assert.Null(await ResolveAsync("submit", "other-operation-secret", environmentId, catalogId));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", Guid.NewGuid(), catalogId));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, Guid.NewGuid()));
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId, 2));

        await using (NpgsqlCommand disable = new("UPDATE gateway.provider_resource_catalog_version SET status='disabled' WHERE id=$1", owner))
        {
            disable.Parameters.AddWithValue(catalogId); _ = await disable.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
        Assert.Null(await ResolveAsync("submit", "sample-vendor-api-key", environmentId, catalogId));
        await ApplyMigrationAsync(owner);
        await using NpgsqlTransaction replay = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, replay, "SET LOCAL ROLE gateway_runtime");
        Assert.Equal(false, await new NpgsqlCommand("SELECT has_table_privilege('gateway_runtime','gateway.provider_resource_locator','SELECT')", owner, replay).ExecuteScalarAsync(TestContext.Current.CancellationToken));
        await replay.RollbackAsync(TestContext.Current.CancellationToken);
        Assert.Equal(false, await new NpgsqlCommand("SELECT has_schema_privilege('gateway_locator_owner','gateway','CREATE')", owner).ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_admin_pagination_has_total_order_and_empty_page_count_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource pool = new(connectionString);
        PostgresGatewayRegistry registry = new(pool.Value);
        PostgresAdminDirectoryStore directory = new(pool);
        DateTimeOffset tiedCreatedAt = DateTimeOffset.UtcNow;
        string prefix = "page-" + Guid.NewGuid().ToString("N");
        Guid foreignTenantId = Guid.NewGuid();
        Guid foreignApplicationId = Guid.NewGuid();
        Guid[] tenantIds = Enumerable.Range(0, 101).Select(_ => Guid.NewGuid()).ToArray();
        Guid[] applicationIds = Enumerable.Range(0, 101).Select(_ => Guid.NewGuid()).ToArray();
        List<Guid> createdTenantIds = [];
        List<Guid> createdApplicationIds = [];
        bool foreignTenantCreated = false;
        bool foreignApplicationCreated = false;
        try
        {
            await registry.AddTenantAsync(new(foreignTenantId, $"{prefix}-z-foreign-tenant", "Foreign tenant", TenantStatus.Active, tiedCreatedAt), TestContext.Current.CancellationToken);
            foreignTenantCreated = true;
            await registry.AddApplicationAsync(new(foreignApplicationId, $"{prefix}-z-foreign-application", "Foreign application", ApplicationStatus.Active, "1.0.0", null, tiedCreatedAt), TestContext.Current.CancellationToken);
            foreignApplicationCreated = true;

            for (int index = 0; index < 101; index++)
            {
                await registry.AddTenantAsync(new(tenantIds[index], $"{prefix}-t-{index:D3}", $"Tenant {index:D3}", TenantStatus.Active, tiedCreatedAt), TestContext.Current.CancellationToken);
                createdTenantIds.Add(tenantIds[index]);
                await registry.AddApplicationAsync(new(applicationIds[index], $"{prefix}-a-{index:D3}", $"Application {index:D3}", ApplicationStatus.Active, "1.0.0", null, tiedCreatedAt), TestContext.Current.CancellationToken);
                createdApplicationIds.Add(applicationIds[index]);
            }

            Assert.Equal(101, createdTenantIds.Count);
            Assert.Equal(101, createdApplicationIds.Count);
            await AssertOwnedPaginationAsync<TenantRecord>((offset, limit, token) => directory.ListTenantsAsync(offset, limit, token), record => record.Id, tenantIds, foreignTenantId, TestContext.Current.CancellationToken);
            await AssertOwnedPaginationAsync<ApplicationRecord>((offset, limit, token) => directory.ListApplicationsAsync(offset, limit, token), record => record.Id, applicationIds, foreignApplicationId, TestContext.Current.CancellationToken);
            AdminPage<TenantRecord> searchedTenant = await directory.ListTenantsAsync(0, 1, TestContext.Current.CancellationToken, $"{prefix}-t-100".ToUpperInvariant());
            Assert.Equal(tenantIds[100], Assert.Single(searchedTenant.Items).Id);
            Assert.Equal(1, searchedTenant.Total);
            Assert.Empty((await directory.ListTenantsAsync(0, 20, TestContext.Current.CancellationToken, "%_' OR 1=1 --")).Items);
            AdminPage<ApplicationRecord> searchedApplication = await directory.ListApplicationsAsync(0, 1, TestContext.Current.CancellationToken, $"{prefix}-a-100");
            Assert.Equal(applicationIds[100], Assert.Single(searchedApplication.Items).Id);

            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=ANY($1)", TestContext.Current.CancellationToken, createdTenantIds.ToArray());
            createdTenantIds.Clear();
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=ANY($1)", TestContext.Current.CancellationToken, createdApplicationIds.ToArray());
            createdApplicationIds.Clear();
            Assert.Equal(1L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.tenant WHERE id=$1", foreignTenantId));
            Assert.Equal(1L, await ScalarAsync(pool.Value, "SELECT count(*) FROM gateway.application WHERE id=$1", foreignApplicationId));
        }
        finally
        {
            try
            {
                if (createdTenantIds.Count > 0)
                    await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=ANY($1)", CancellationToken.None, createdTenantIds.ToArray());
            }
            finally
            {
                try
                {
                    if (createdApplicationIds.Count > 0)
                        await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=ANY($1)", CancellationToken.None, createdApplicationIds.ToArray());
                }
                finally
                {
                    try
                    {
                        if (foreignTenantCreated)
                            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.tenant WHERE id=$1", CancellationToken.None, foreignTenantId);
                    }
                    finally
                    {
                        if (foreignApplicationCreated)
                            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.application WHERE id=$1", CancellationToken.None, foreignApplicationId);
                    }
                }
            }
        }
    }

    [Fact]
    public async Task M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        NpgsqlDataSource dataSource = adminPool.Value;
        await ApplyMigrationAsync();
        PostgresConnectorConfigurationStore store = new(dataSource);
        PostgresGatewayRegistry registry = new(dataSource);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://m4-postgres.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://m4-postgres.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        Guid suffix = Guid.NewGuid();
        string connectorId = "postgres-" + suffix.ToString("N");
        Guid environmentId = Guid.NewGuid();
        await registry.AddEnvironmentAsync(new(environmentId, "m4-" + suffix.ToString("N")[..20], "M4", false), TestContext.Current.CancellationToken);
        TestProviderResources resources = await RegisterTestResourcesAsync(store, environmentId, connectorId, clock.UtcNow);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));

        async Task<ConnectorVersionResource> ImportPublishAsync(string version, long revision)
        {
            string candidate = source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal).Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal);
            using JsonDocument definition = JsonDocument.Parse(candidate);
            ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
                new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, null,
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }, version), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, version, TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Imported version missing.");
            byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
            ConnectorApprovalRecord request = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
            _ = await store.ApproveCanonicalAsync(security, request.Id, stored.Id, Convert.ToHexString(digest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken);
            return await admin.PublishAsync(connectorId, version, validated.RowVersion, revision, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        }

        ConnectorVersionResource v1 = await ImportPublishAsync("1.0.0", 0);
        GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, "submit", environmentId, TestContext.Current.CancellationToken);
        Assert.Equal("1.0.0", operation.Version);

        ConnectorVersionResource v2 = await ImportPublishAsync("2.0.0", 1);
        ConnectorVersionResource rolledBack = await admin.RollbackAsync(connectorId, new("1.0.0", v2.RowVersion), "postgres-test", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(v1.ChecksumSha256, rolledBack.ChecksumSha256);
        Assert.Equal("1.0.0", (await catalog.GetRequiredAsync(connectorId, "submit", environmentId, TestContext.Current.CancellationToken)).Version);

        await using NpgsqlConnection tamperConnection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand tamper = new("UPDATE gateway.connector_version SET configuration_json='{}'::jsonb WHERE id=$1", tamperConnection);
        tamper.Parameters.AddWithValue((await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken))!.Id);
        PostgresException immutable = await Assert.ThrowsAsync<PostgresException>(() => tamper.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        Assert.Equal("23000", immutable.SqlState);
    }

    [Fact]
    public async Task W1_IT_DAT_PostgreSQL18_OAuth_validation_approval_publication_and_operation_locator_resolution_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnectionString)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole = await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(connectionString, migrationConnectionString, TestContext.Current.CancellationToken);
        await using NpgsqlDataSource runtimePool = NpgsqlDataSource.Create(runtimeRole.ConnectionString);
        RoutingConnectorConfigurationStore store = new(adminPool, runtimePool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        string suffix = Guid.NewGuid().ToString("N");
        string connectorId = "oauth-pg-" + suffix;
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        await registry.AddTenantAsync(new(tenantId, "ow1-t-" + suffix, "OAuth tenant", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "ow1-a-" + suffix, "OAuth application", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "ow1-e-" + suffix[..20], "OAuth environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorId, "invoke", true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        ProviderResourceCatalogRecord registered = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "oauth-secret-" + suffix,
            ProviderResourceType.Secret, "OAuth client secret", environmentId, connectorId, "invoke", "synthetic://oauth-controlled-" + suffix,
            ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        using JsonDocument definition = JsonDocument.Parse($$"""
        {
          "schemaVersion":"1.0","connectorId":"{{connectorId}}","version":"1.0.0","displayName":"OAuth PostgreSQL path",
          "bindings":{"endpoints":[{"name":"protected-api"},{"name":"oauth-authorize"},{"name":"oauth-token"}],"secrets":[{"name":"oauth-client-secret","kind":"opaque"}]},
          "operations":[
            {"operationId":"invoke","endpointBinding":"protected-api","method":"GET","path":"/resource","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"oauthAuthorizationCode","profileId":"postgres.oauth","authorizationEndpointBinding":"oauth-authorize","tokenEndpointBinding":"oauth-token","clientId":"postgres-client","clientAuthMethod":"client_secret_basic","secretBinding":"oauth-client-secret","scopes":["read"],"redirectUri":"https://gateway.example.test/callback","pkcePolicy":"S256_REQUIRED"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://oauth-pg.invalid", "editor-" + suffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://oauth-pg.invalid", "approver-" + suffix, "Approver", null), TestContext.Current.CancellationToken);
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, "1.0.0", imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string>
            {
                ["protected-api"] = "https://api.example.test/",
                ["oauth-authorize"] = "https://identity.example.test/authorize",
                ["oauth-token"] = "https://identity.example.test/token"
            },
            new Dictionary<string, ProviderResourceReference> { ["oauth-client-secret"] = new(registered.ProviderId, registered.ResourceId, registered.ResourceType) }, null, null, "1.0.0"),
            editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("OAuth version missing.");
        ConnectorBindingSet binding = Assert.Single((await store.ListBindingsPageAsync(stored.Id, 0, 10, environmentId, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        Assert.Equal(["oauth-authorize", "oauth-token"], Assert.Single(review.Artifact.Operations).BindingDependencies.AuthorityEndpointBindingIds);
        byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        Assert.Equal(review.DigestSha256, Convert.ToHexString(digest));
        ConnectorApprovalRecord request = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await store.ApproveCanonicalAsync(security, request.Id, stored.Id, review.DigestSha256, stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken);
        _ = await admin.PublishAsync(connectorId, "1.0.0", validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);

        PublishedConnectorAccessContext access = new(installationId, tenantId, applicationId, "invoke");
        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, access, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published OAuth snapshot missing.");
        Assert.Equal("synthetic://oauth-controlled-" + suffix, Assert.Single(snapshot.SecretProviderReferences).Value);
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
            Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "3.0.0", null);
        PublishedOAuthAuthorityResolver resolver = new(store, new NeverReadSecretProvider(), clock);
        OAuthResolvedExecutionContext resolved = await resolver.ResolveAsync(new OAuthAuthorizedInvocation(new GatewayClientPrincipal(identity, Guid.NewGuid()), connectorId, "invoke"),
            new OAuthAuthorityRequest("postgres.oauth"), TestContext.Current.CancellationToken);
        Assert.Equal("postgres.oauth", resolved.ProfileId);
        Assert.Equal(connectorId, resolved.ConnectorId);
    }

    [Fact]
    public async Task Wave1_IT_DAT_PostgreSQL18_composed_SOAP_validation_four_eyes_publication_and_authority_resolution_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnectionString)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole = await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(connectionString, migrationConnectionString, TestContext.Current.CancellationToken);
        await using NpgsqlDataSource runtimePool = NpgsqlDataSource.Create(runtimeRole.ConnectionString);
        RoutingConnectorConfigurationStore store = new(adminPool, runtimePool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        string suffix = Guid.NewGuid().ToString("N");
        string connectorId = "soap-pg-" + suffix;
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        await registry.AddTenantAsync(new(tenantId, "sw1-t-" + suffix, "SOAP tenant", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "sw1-a-" + suffix, "SOAP application", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "sw1-e-" + suffix[..20], "SOAP environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorId, "invoke", true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        foreach (string resourceId in new[] { "basic-user-" + suffix, "basic-password-" + suffix, "session-resource-" + suffix })
        {
            _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", resourceId,
                ProviderResourceType.Secret, resourceId, environmentId, connectorId, "invoke", "synthetic://" + resourceId,
                ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        }
        using JsonDocument definition = JsonDocument.Parse($$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"1.0.0","displayName":"Composed SOAP PostgreSQL path",
          "bindings":{"endpoints":[{"name":"soap-service"}],"secrets":[{"name":"basic-username","kind":"username"},{"name":"basic-password","kind":"password"},{"name":"session-resource","kind":"opaque"}]},
          "operations":[
            {"operationId":"invoke","endpointBinding":"soap-service","method":"POST","path":"/service","request":{"contentType":"text/xml","maximumBytes":1048576},"response":{"maximumBytes":1048576},"authentication":{"kind":"soapBasicOpaqueSession","policyId":"postgres.composed","sessionProfileId":"postgres.session","usernameBinding":"basic-username","passwordBinding":"basic-password","secretBinding":"session-resource","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue","soapHttp":{"version":"1.1","action":"urn:synthetic:postgres:invoke"}},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://soap-pg.invalid", "editor-" + suffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://soap-pg.invalid", "approver-" + suffix, "Approver", null), TestContext.Current.CancellationToken);
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, "1.0.0", imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["soap-service"] = "https://soap.example.test/" },
            new Dictionary<string, ProviderResourceReference>
            {
                ["basic-username"] = new("synthetic", "basic-user-" + suffix, ProviderResourceType.Secret),
                ["basic-password"] = new("synthetic", "basic-password-" + suffix, ProviderResourceType.Secret),
                ["session-resource"] = new("synthetic", "session-resource-" + suffix, ProviderResourceType.Secret)
            }, null, null, "1.0.0"), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Composed SOAP version missing.");
        ConnectorBindingSet binding = Assert.Single((await store.ListBindingsPageAsync(stored.Id, 0, 10, environmentId, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        Assert.Equal(["basic-password", "basic-username", "session-resource"], Assert.Single(review.Artifact.Operations).BindingDependencies.SecretBindingIds);
        byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        Assert.Equal(review.DigestSha256, Convert.ToHexString(digest));
        ConnectorApprovalRecord approvalRequest = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, review.DigestSha256, stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken);
        _ = await admin.PublishAsync(connectorId, "1.0.0", validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);

        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
            Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "3.0.0", null);
        PublishedComposedSoapAuthorityResolver resolver = new(store, clock);
        ComposedSoapResolvedExecutionContext resolved = await resolver.ResolveAsync(new(new GatewayClientPrincipal(identity, Guid.NewGuid()), connectorId, "invoke"),
            new OpaqueSessionHttpAuthorityRequest("postgres.composed"), TestContext.Current.CancellationToken);
        Assert.Equal(connectorId, resolved.ConnectorId);
        Assert.Equal(SoapEnvelopeVersion.Soap11, resolved.SoapHttp.Version);
        Assert.Equal("urn:synthetic:postgres:invoke", resolved.SoapHttp.Action);
    }

    [Fact]
    public async Task Wave1_IT_DAT_PostgreSQL18_typed_session_four_eyes_publication_and_runtime_locator_resolution_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnectionString)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole = await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(connectionString, migrationConnectionString, TestContext.Current.CancellationToken);
        await using NpgsqlDataSource runtimePool = NpgsqlDataSource.Create(runtimeRole.ConnectionString);
        RoutingConnectorConfigurationStore store = new(adminPool, runtimePool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        string suffix = Guid.NewGuid().ToString("N");
        string connectorId = "typed-pg-" + suffix;
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        await registry.AddTenantAsync(new(tenantId, "tw1pg-t-" + suffix, "Typed PG tenant", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "tw1pg-a-" + suffix, "Typed PG application", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "tw1pg-e-" + suffix[..20], "Typed PG environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorId, "session-bootstrap", true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        ProviderResourceCatalogRecord username = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "typed-user-" + suffix,
            ProviderResourceType.Secret, "Typed username", environmentId, connectorId, "session-bootstrap", "synthetic://typed-user-" + suffix,
            ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord password = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "typed-password-" + suffix,
            ProviderResourceType.Secret, "Typed password", environmentId, connectorId, "session-bootstrap", "synthetic://typed-password-" + suffix,
            ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        using JsonDocument definition = JsonDocument.Parse(ConnectorRuntime.Auth.Soap.TypedSessionHandshakeRealHttpIntegrationTests.ProductionDefinition(connectorId));
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://typed-pg.invalid", "editor-" + suffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://typed-pg.invalid", "approver-" + suffix, "Approver", null), TestContext.Current.CancellationToken);
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, "1.0.0", imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["soap"] = "https://typed-session.example.test/" },
            new Dictionary<string, ProviderResourceReference>
            {
                ["username"] = new(username.ProviderId, username.ResourceId, username.ResourceType),
                ["password"] = new(password.ProviderId, password.ResourceId, password.ResourceType)
            }, null, null, "1.0.0"), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, "1.0.0", TestContext.Current.CancellationToken) ?? throw new InvalidOperationException("Typed version missing.");
        ConnectorBindingSet binding = Assert.Single((await store.ListBindingsPageAsync(stored.Id, 0, 10, environmentId, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        Assert.Equal("session-admission-validation", Assert.Single(Assert.Single(review.Artifact.Operations).AuthorityEndpoints).Role);
        byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approvalRequest = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        GatewayException selfApproval = await Assert.ThrowsAsync<GatewayException>(() => store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id,
            Convert.ToHexString(digest), stored.CreatedBy, editor.Id, null, Guid.NewGuid(), clock.UtcNow.AddMilliseconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-FOUR-EYES", selfApproval.Code);
        _ = await store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, Convert.ToHexString(digest), stored.CreatedBy, approver.Id, null,
            Guid.NewGuid(), clock.UtcNow.AddMilliseconds(2), TestContext.Current.CancellationToken);
        GatewayException wrongCurrentDigest = await Assert.ThrowsAsync<GatewayException>(() => store.PublishApprovedAsync(stored.Id, new byte[32], validated.RowVersion, 0,
            approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddMilliseconds(3), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-ADMIN-APPROVAL-STALE", wrongCurrentDigest.Code);
        _ = await admin.PublishAsync(connectorId, "1.0.0", validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);

        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId,
            new(installationId, tenantId, applicationId, "session-bootstrap"), TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published typed snapshot missing.");
        Assert.Equal(2, snapshot.SecretProviderReferences.Count);
        Assert.Equal(ConnectorVersionState.Published, snapshot.Version.State);
        Assert.Equal(binding.Revision, snapshot.Bindings.Revision);
    }

    [Fact]
    public async Task M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await ApplyMigrationAsync();
        PostgresConnectorConfigurationStore store = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        TestClock clock = new(DateTimeOffset.UtcNow);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new DevelopmentConnectorApprovalPolicy());
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://m5-postgres.invalid", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        string connectorId = "atomic-" + Guid.NewGuid().ToString("N");
        await registry.AddEnvironmentAsync(new(environmentId, "a-" + Guid.NewGuid().ToString("N")[..20], "Atomic", false), TestContext.Current.CancellationToken);
        TestProviderResources resources = await RegisterTestResourcesAsync(store, environmentId, connectorId, clock.UtcNow);
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, imported.Version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://approved.example.test/" },
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, null,
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
        byte[] approvedDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approvalRequest = await security.RequestApprovalAsync(stored, approvedDigest, editor.Id, Guid.NewGuid(), clock.UtcNow, TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord previousResource = await store.ResolveProviderResourceAsync(resources.SecretReference, environmentId, connectorId, ["submit"], TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord rotatedResource = await store.RegisterProviderResourceAsync(previousResource with { Id = Guid.NewGuid(), ProviderReference = "synthetic://rotated-api-key", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = clock.UtcNow.AddMilliseconds(1) }, TestContext.Current.CancellationToken);
        GatewayException staleReview = await Assert.ThrowsAsync<GatewayException>(() => store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, Convert.ToHexString(approvedDigest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", staleReview.Code);
        Dictionary<string, ProviderResourceBinding> refreshedSecrets = new() { ["sample-vendor-api-key"] = Binding(rotatedResource) };
        _ = await store.PutBindingsAsync(new(Guid.NewGuid(), stored.ConnectorId, stored.Id, environmentId,
            new Dictionary<string, Uri> { ["sample-vendor-endpoint"] = new("https://approved.example.test/") }, refreshedSecrets,
            new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-client-certificate"] = resources.CertificateBinding }, 0,
            ConnectorBindingDigests.Revision(stored.Id, environmentId, new Dictionary<string, Uri> { ["sample-vendor-endpoint"] = new("https://approved.example.test/") }, refreshedSecrets, new Dictionary<string, ProviderResourceBinding> { ["sample-vendor-client-certificate"] = resources.CertificateBinding }),
            ConnectorBindingState.Draft, clock.UtcNow.AddSeconds(1), editor.Id.ToString("D")), 1, Guid.NewGuid(), TestContext.Current.CancellationToken);
        approvedDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        approvalRequest = await security.RequestApprovalAsync(stored, approvedDigest, editor.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(1), TestContext.Current.CancellationToken);
        _ = await store.ApproveCanonicalAsync(security, approvalRequest.Id, stored.Id, Convert.ToHexString(approvedDigest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(2), TestContext.Current.CancellationToken);

        await using NpgsqlConnection blocker = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlTransaction blockerTransaction = await blocker.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await using (NpgsqlCommand lockVersion = new("SELECT id FROM gateway.connector_version WHERE id=$1 FOR UPDATE", blocker, blockerTransaction))
        {
            lockVersion.Parameters.AddWithValue(stored.Id);
            _ = await lockVersion.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        }
        Task<long> mutation = admin.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://controlled-attacker.example.test/" },
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = resources.SecretReference }, 2,
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = resources.CertificateReference }), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
        await WaitForVersionLockWaitAsync(adminPool.Value, TestContext.Current.CancellationToken);
        Task<ConnectorVersionRecord> publication = store.PublishApprovedAsync(stored.Id, approvedDigest, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(2), TestContext.Current.CancellationToken);
        await blockerTransaction.CommitAsync(TestContext.Current.CancellationToken);

        long? mutationRevision = null;
        ConnectorVersionRecord? firstPublication = null;
        Exception? mutationFailure = null;
        Exception? publicationFailure = null;
        try { mutationRevision = await mutation; } catch (Exception exception) { mutationFailure = exception; }
        try { firstPublication = await publication; } catch (Exception exception) { publicationFailure = exception; }
        Assert.NotEqual(mutationFailure is null, publicationFailure is null);

        await using NpgsqlConnection auditConnection = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand audit = new("SELECT count(*) FROM gateway.audit_event WHERE action='connector.publish' AND target_id=$1", auditConnection);
        audit.Parameters.AddWithValue(connectorId + "/" + imported.Version);
        ConnectorVersionRecord published;
        string expectedEndpoint;
        if (mutationFailure is null)
        {
            Assert.Equal(3, mutationRevision);
            GatewayException denied = Assert.IsType<GatewayException>(publicationFailure);
            Assert.True(denied.Code is "BGW-ADMIN-APPROVAL-STALE" or "BGW-ADMIN-APPROVAL-REQUIRED" or "BGW-CONCURRENCY-CONFLICT", denied.Code);
            ConnectorVersionRecord after = (await store.GetVersionAsync(connectorId, imported.Version, TestContext.Current.CancellationToken))!;
            Assert.Equal(ConnectorVersionState.Validated, after.State);
            Assert.Equal(0L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));
            byte[] currentDigest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
            ConnectorApprovalRecord currentRequest = await security.RequestApprovalAsync(after, currentDigest, editor.Id, Guid.NewGuid(), clock.UtcNow.AddSeconds(3), TestContext.Current.CancellationToken);
            _ = await store.ApproveCanonicalAsync(security, currentRequest.Id, after.Id, Convert.ToHexString(currentDigest), after.CreatedBy, approver.Id, null, Guid.NewGuid(), clock.UtcNow.AddSeconds(4), TestContext.Current.CancellationToken);
            published = await store.PublishApprovedAsync(after.Id, currentDigest, after.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow.AddSeconds(5), TestContext.Current.CancellationToken);
            expectedEndpoint = "https://controlled-attacker.example.test/";
        }
        else
        {
            GatewayException denied = Assert.IsType<GatewayException>(mutationFailure);
            Assert.Equal("BGW-CONCURRENCY-CONFLICT", denied.Code);
            Assert.Null(publicationFailure);
            published = Assert.IsType<ConnectorVersionRecord>(firstPublication);
            expectedEndpoint = "https://approved.example.test/";
        }
        Assert.Equal(ConnectorVersionState.Published, published.State);
        Assert.Equal(1L, await audit.ExecuteScalarAsync(TestContext.Current.CancellationToken));

        AdminPage<ConnectorBindingSet> bindingPage = await store.ListBindingsPageAsync(published.Id, 0, 10, environmentId, TestContext.Current.CancellationToken);
        ConnectorBindingSet activeBinding = Assert.Single(bindingPage.Items, value => value.State == ConnectorBindingState.Active);
        await using NpgsqlConnection tamperConnection = await adminPool.Value.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using (NpgsqlCommand roleCheck = new("SELECT rolsuper FROM pg_roles WHERE rolname=current_user", tamperConnection))
            Assert.False((bool)(await roleCheck.ExecuteScalarAsync(TestContext.Current.CancellationToken))!);

        async Task AssertBindingTamperDeniedAsync(string assignment, object value)
        {
            await using NpgsqlCommand command = new($"UPDATE gateway.connector_binding_bundle_version SET {assignment}=$2 WHERE id=$1", tamperConnection);
            command.Parameters.AddWithValue(activeBinding.Id);
            command.Parameters.AddWithValue(value);
            _ = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        }

        await AssertBindingTamperDeniedAsync("endpoints_json", JsonSerializer.Serialize(new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://tamper.invalid/" }));
        await AssertBindingTamperDeniedAsync("checksum_sha256", RandomNumberGenerator.GetBytes(32));
        await AssertBindingTamperDeniedAsync("connector_id", "tampered-connector");
        await AssertBindingTamperDeniedAsync("environment_id", Guid.NewGuid());
        await AssertBindingTamperDeniedAsync("revision", activeBinding.Revision + 1);
        await AssertBindingTamperDeniedAsync("state", "draft");

        PublishedConnectorSnapshot unchanged = await store.GetPublishedSnapshotAsync(connectorId, environmentId, null, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published snapshot disappeared after a rejected tamper attempt.");
        Assert.Equal(expectedEndpoint, unchanged.Bindings.Endpoints["sample-vendor-endpoint"].AbsoluteUri);
        Assert.Equal(activeBinding.Revision, unchanged.Bindings.Revision);
        Assert.Equal(activeBinding.ChecksumSha256, unchanged.Bindings.ChecksumSha256);
    }

    [Fact]
    public async Task M5_IT_DAT_Fault_injection_rolls_back_admin_state_and_audit_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION") ?? connectionString;
        await using AdminPostgresDataSource adminPool = new(migrationConnectionString);
        await using AdminPostgresDataSource storePool = new(connectionString);
        await ApplyMigrationAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        PostgresGatewayRegistry setupRegistry = new(storePool.Value);
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid();
        await setupRegistry.AddTenantAsync(new(tenantId, "fault-" + tenantId.ToString("N"), "Fault tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddApplicationAsync(new(applicationId, "fault-" + applicationId.ToString("N"), "Fault app", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await setupRegistry.AddEnvironmentAsync(new(environmentId, "f-" + environmentId.ToString("N")[..20], "Fault environment", false), TestContext.Current.CancellationToken);

        Guid failedTenantId = Guid.NewGuid(); Guid failedTenantCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedTenant = new(storePool.Value, new ThrowingFaultInjector("tenant.create.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedTenant.AddTenantWithAuditAsync(new(failedTenantId, "failed-" + failedTenantId.ToString("N"), "Failed tenant", TenantStatus.Active, now), Audit(failedTenantId, failedTenantCorrelation, "tenant.create", failedTenantId.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.tenant WHERE id=$1", failedTenantId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedTenantCorrelation));

        Guid failedApplicationId = Guid.NewGuid(); Guid failedApplicationCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedApplication = new(storePool.Value, new ThrowingFaultInjector("application.create.after-state"));
        GatewayAuditEvent applicationAudit = new(Guid.NewGuid(), now, null, "administrator", "fault-test", "application.create", "application", failedApplicationId.ToString("D"), failedApplicationCorrelation, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApplication.AddApplicationWithAuditAsync(new(failedApplicationId, "failed-" + failedApplicationId.ToString("N"), "Failed application", ApplicationStatus.Active, "1.0.0", null, now), applicationAudit, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.application WHERE id=$1", failedApplicationId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedApplicationCorrelation));

        foreach (string point in new[] { "tenant.update.after-state", "tenant.disable.after-state" })
        {
            Guid correlation = Guid.NewGuid(); PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
            Task mutation = point.Contains("update", StringComparison.Ordinal)
                ? faulted.UpdateTenantWithAuditAsync(tenantId, "Tampered tenant", 1, Audit(tenantId, correlation, "tenant.update", tenantId.ToString("D"), now), TestContext.Current.CancellationToken)
                : faulted.DisableTenantWithAuditAsync(tenantId, 1, Audit(tenantId, correlation, "tenant.disable", tenantId.ToString("D"), now), TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<InjectedFailureException>(() => mutation);
            Assert.Equal("Fault tenant", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal("active", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlation));
        }

        foreach (string point in new[] { "application.update.after-state", "application.disable.after-state" })
        {
            Guid correlation = Guid.NewGuid(); PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
            GatewayAuditEvent eventValue = new(Guid.NewGuid(), now, null, "administrator", "fault-test", point.Replace(".after-state", "", StringComparison.Ordinal), "application", applicationId.ToString("D"), correlation, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());
            Task mutation = point.Contains("update", StringComparison.Ordinal)
                ? faulted.UpdateApplicationWithAuditAsync(applicationId, "Tampered app", "9.0.0", null, 1, eventValue, TestContext.Current.CancellationToken)
                : faulted.DisableApplicationWithAuditAsync(applicationId, 1, eventValue, TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<InjectedFailureException>(() => mutation);
            Assert.Equal("Fault app", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.application WHERE id=$1", applicationId));
            Assert.Equal("active", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.application WHERE id=$1", applicationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlation));
        }

        using (CancellationTokenSource cancelled = new())
        {
            cancelled.Cancel(); Guid cancellationCorrelation = Guid.NewGuid();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => setupRegistry.UpdateTenantWithAuditAsync(tenantId, "Cancelled tenant", 1, Audit(tenantId, cancellationCorrelation, "tenant.update", tenantId.ToString("D"), now), cancelled.Token));
            Assert.Equal("Fault tenant", await TextScalarAsync(adminPool.Value, "SELECT display_name FROM gateway.tenant WHERE id=$1", tenantId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", cancellationCorrelation));
        }

        foreach (string point in new[] { "installation.create.after-installation", "installation.create.after-activation" })
        {
            Guid installationId = Guid.NewGuid(); Guid activationId = Guid.NewGuid(); Guid correlationId = Guid.NewGuid();
            PostgresGatewayRegistry faulted = new(storePool.Value, new ThrowingFaultInjector(point));
            await Assert.ThrowsAsync<InjectedFailureException>(() => faulted.AddInstallationActivationWithAuditAsync(
                new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, now),
                new(activationId, installationId, SHA256.HashData(Guid.NewGuid().ToByteArray()), now.AddHours(1), now, "fault-test"),
                Audit(tenantId, correlationId, "installation.create", installationId.ToString("D"), now), TestContext.Current.CancellationToken));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.installation WHERE id=$1", installationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.activation_code WHERE id=$1", activationId));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", correlationId));
        }

        Guid activeInstallation = Guid.NewGuid();
        await setupRegistry.AddInstallationAsync(new(activeInstallation, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, now), TestContext.Current.CancellationToken);
        using JsonDocument grantSource = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        string grantConnectorId = "fault-grant-" + Guid.NewGuid().ToString("N");
        using JsonDocument grantDefinition = JsonDocument.Parse(grantSource.RootElement.GetRawText().Replace("sample-secure-service", grantConnectorId, StringComparison.Ordinal));
        ValidatedConnectorDefinition grantCanonical = new ConnectorDefinitionValidator().ValidateRequired(grantDefinition.RootElement);
        PostgresConnectorConfigurationStore grantConnectorStore = new(storePool.Value);
        ConnectorVersionRecord grantDraft = await grantConnectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, grantConnectorId, grantCanonical.Version, grantCanonical.SchemaVersion, ConnectorVersionState.Draft, grantCanonical.CanonicalJson, Convert.FromHexString(grantCanonical.ChecksumSha256), "fault-test", now, 0), TestContext.Current.CancellationToken);
        ConnectorVersionRecord grantVersion = await grantConnectorStore.MarkValidatedAsync(grantDraft.Id, grantDraft.RowVersion, now, TestContext.Current.CancellationToken);
        Guid grantId = Guid.NewGuid(); Guid grantCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedGrant = new(storePool.Value, new ThrowingFaultInjector("grant.create.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedGrant.AddGrantWithAuditAsync(new(grantId, activeInstallation, tenantId, grantConnectorId, "submit", true, now), grantVersion, Audit(tenantId, grantCorrelation, "grant.create", grantId.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.installation_connector_grant WHERE id=$1", grantId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", grantCorrelation));

        Guid revokeCorrelation = Guid.NewGuid();
        PostgresGatewayRegistry faultedRevocation = new(storePool.Value, new ThrowingFaultInjector("installation.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRevocation.RevokeInstallationWithAuditAsync(activeInstallation, "fault test", now, Audit(tenantId, revokeCorrelation, "installation.revoke", activeInstallation.ToString("D"), now), TestContext.Current.CancellationToken));
        Assert.Equal("pending", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.installation WHERE id=$1", activeInstallation));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", revokeCorrelation));

        PostgresAdminSecurityStore security = new(storePool);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://fault.example.test", "editor-" + Guid.NewGuid().ToString("N"), "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://fault.example.test", "approver-" + Guid.NewGuid().ToString("N"), "Approver", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord bootstrapPrincipal = await security.EnsurePrincipalAsync(new("https://fault.example.test", "bootstrap-" + Guid.NewGuid().ToString("N"), "Bootstrap", null), TestContext.Current.CancellationToken);
        Guid bootstrapCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedBootstrap = new(storePool, new ThrowingFaultInjector("admin.bootstrap.after-state"));
        await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_bootstrap", TestContext.Current.CancellationToken);
        try
        {
            await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBootstrap.TryBootstrapSecurityAdministratorAsync(bootstrapPrincipal.Id, bootstrapCorrelation, now, TestContext.Current.CancellationToken));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_bootstrap WHERE principal_id=$1", bootstrapPrincipal.Id));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", bootstrapPrincipal.Id));
            Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bootstrapCorrelation));
        }
        finally
        {
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_role_assignment WHERE principal_id=$1", CancellationToken.None, bootstrapPrincipal.Id);
            await ExecuteNonQueryAsync(migrationConnectionString, "DELETE FROM gateway.admin_bootstrap WHERE principal_id=$1", CancellationToken.None, bootstrapPrincipal.Id);
        }

        Guid roleCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRole = new(storePool, new ThrowingFaultInjector("admin.role.assign.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRole.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, roleCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1", editor.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleCorrelation));
        AdminRoleAssignmentRecord assignment = await security.AssignRoleAsync(editor.Id, AdminRole.Viewer, null, approver.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid roleRevokeCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedRoleRevoke = new(storePool, new ThrowingFaultInjector("admin.role.revoke.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRoleRevoke.RevokeRoleAsync(assignment.Id, approver.Id, roleRevokeCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(1L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.admin_role_assignment WHERE id=$1", assignment.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", roleRevokeCorrelation));

        ConnectorDefinitionValidator validator = new();
        using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(FindRepositoryRoot(), "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
        string connectorId = "fault-" + Guid.NewGuid().ToString("N");
        using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
        ValidatedConnectorDefinition canonical = validator.ValidateRequired(definition.RootElement);
        PostgresConnectorConfigurationStore connectorStore = new(storePool.Value);
        Guid failedImportCorrelation = Guid.NewGuid(); Guid failedDraftId = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedImport = new(storePool.Value, new ThrowingFaultInjector("connector.import.after-state"));
        GatewayAuditEvent importAudit = new(Guid.NewGuid(), now, null, "administrator", editor.Id.ToString("D"), "connector.import", "connectorVersion", connectorId + "/" + canonical.Version, failedImportCorrelation, "success", "BGW-CONNECTOR-IMPORTED", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedImport.CreateDraftWithAuditAsync(new(failedDraftId, Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), editor.Id.ToString("D"), now, 0), importAudit, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_version WHERE id=$1", failedDraftId));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedImportCorrelation));
        ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), editor.Id.ToString("D"), now, 0), TestContext.Current.CancellationToken);
        Guid failedValidationCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedValidation = new(storePool.Value, new ThrowingFaultInjector("connector.validate.after-state"));
        GatewayAuditEvent validationAudit = new(Guid.NewGuid(), now, null, "administrator", editor.Id.ToString("D"), "connector.validate", "connectorVersion", connectorId + "/" + canonical.Version, failedValidationCorrelation, "success", "BGW-CONNECTOR-VALIDATED", new Dictionary<string, string>());
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedValidation.MarkValidatedWithAuditAsync(draft.Id, draft.RowVersion, now, validationAudit, TestContext.Current.CancellationToken));
        Assert.Equal("draft", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", draft.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", failedValidationCorrelation));
        ConnectorVersionRecord validated = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, now, TestContext.Current.CancellationToken);
        Guid approvalCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedApproval = new(storePool, new ThrowingFaultInjector("connector.approval.request.after-state"));
        byte[] provisionalDigest = SHA256.HashData("provisional"u8);
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApproval.RequestApprovalAsync(validated, provisionalDigest, editor.Id, approvalCorrelation, now, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_approval WHERE connector_version_id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approvalCorrelation));

        Guid bindingCorrelation = Guid.NewGuid();
        Dictionary<string, Uri> endpoints = new() { ["sample-vendor-endpoint"] = new("https://vendor.example.test/") };
        TestProviderResources resources = await RegisterTestResourcesAsync(connectorStore, environmentId, connectorId, now);
        Dictionary<string, ProviderResourceBinding> secrets = new() { ["sample-vendor-api-key"] = resources.SecretBinding };
        Dictionary<string, ProviderResourceBinding> certificates = new() { ["sample-vendor-client-certificate"] = resources.CertificateBinding };
        ConnectorBindingSet binding = new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints, secrets, certificates, 0,
            ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints, secrets, certificates), ConnectorBindingState.Draft, now, editor.Id.ToString("D"));
        PostgresConnectorConfigurationStore faultedBinding = new(storePool.Value, new ThrowingFaultInjector("connector.binding.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedBinding.PutBindingsAsync(binding, null, bindingCorrelation, TestContext.Current.CancellationToken));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.connector_binding_bundle_version WHERE id=$1", binding.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", bindingCorrelation));

        ConnectorBindingSet storedBinding = await connectorStore.PutBindingsAsync(binding with { Id = Guid.NewGuid() }, null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] digest = await connectorStore.GetBindingBundleDigestAsync(validated.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord firstApprovalRequest = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
        Guid approveCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedApprove = new(storePool.Value, new ThrowingFaultInjector("connector.approval.approve.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedApprove.ApproveCanonicalAsync(security, firstApprovalRequest.Id, validated.Id, Convert.ToHexString(digest), validated.CreatedBy, approver.Id, null, approveCorrelation, now.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", approveCorrelation));
        _ = await connectorStore.ApproveCanonicalAsync(security, firstApprovalRequest.Id, validated.Id, Convert.ToHexString(digest), validated.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(2), TestContext.Current.CancellationToken);
        ConnectorApprovalRecord secondApprovalRequest = await security.RequestApprovalAsync(validated, digest, editor.Id, Guid.NewGuid(), now.AddSeconds(3), TestContext.Current.CancellationToken);
        Guid rejectCorrelation = Guid.NewGuid();
        PostgresAdminSecurityStore faultedReject = new(storePool, new ThrowingFaultInjector("connector.approval.reject.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedReject.RejectAsync(validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, "fault", rejectCorrelation, now.AddSeconds(4), TestContext.Current.CancellationToken));
        Assert.Equal("requested", await TextScalarAsync(adminPool.Value, "SELECT status FROM gateway.connector_approval WHERE connector_version_id=$1 ORDER BY requested_at DESC LIMIT 1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rejectCorrelation));
        _ = await security.ApproveAsync(secondApprovalRequest.Id, validated.Id, validated.ChecksumSha256, digest, validated.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(5), TestContext.Current.CancellationToken);

        Guid retireCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRetire = new(storePool.Value, new ThrowingFaultInjector("connector.retire.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRetire.RetireAsync(validated.Id, validated.RowVersion, approver.Id.ToString("D"), retireCorrelation, now.AddSeconds(6), TestContext.Current.CancellationToken));
        Assert.Equal("validated", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", retireCorrelation));
        Guid publishCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedPublish = new(storePool.Value, new ThrowingFaultInjector("connector.publish.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedPublish.PublishApprovedAsync(validated.Id, digest, validated.RowVersion, 0, approver.Id.ToString("D"), publishCorrelation, now.AddSeconds(7), TestContext.Current.CancellationToken));
        Assert.Equal("validated", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", validated.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", publishCorrelation));
        Assert.Equal(ConnectorBindingState.Draft, storedBinding.State);

        ConnectorVersionRecord publishedV1 = await connectorStore.PublishApprovedAsync(validated.Id, digest, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), now.AddSeconds(8), TestContext.Current.CancellationToken);
        using JsonDocument definitionV2 = JsonDocument.Parse(definition.RootElement.GetRawText().Replace("\"version\": \"1.0.0\"", "\"version\": \"2.0.0\"", StringComparison.Ordinal));
        ValidatedConnectorDefinition canonicalV2 = validator.ValidateRequired(definitionV2.RootElement);
        ConnectorVersionRecord draftV2 = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonicalV2.Version, canonicalV2.SchemaVersion, ConnectorVersionState.Draft, canonicalV2.CanonicalJson, Convert.FromHexString(canonicalV2.ChecksumSha256), editor.Id.ToString("D"), now.AddSeconds(9), 0), TestContext.Current.CancellationToken);
        ConnectorVersionRecord validatedV2 = await connectorStore.MarkValidatedAsync(draftV2.Id, draftV2.RowVersion, now.AddSeconds(10), TestContext.Current.CancellationToken);
        string bindingV2Checksum = ConnectorBindingDigests.Revision(validatedV2.Id, environmentId, endpoints, secrets, certificates);
        _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), validatedV2.ConnectorId, validatedV2.Id, environmentId, endpoints, secrets, certificates, 0, bindingV2Checksum, ConnectorBindingState.Draft, now.AddSeconds(11), editor.Id.ToString("D")), null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] digestV2 = await connectorStore.GetBindingBundleDigestAsync(validatedV2.Id, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approvalRequestV2 = await security.RequestApprovalAsync(validatedV2, digestV2, editor.Id, Guid.NewGuid(), now.AddSeconds(12), TestContext.Current.CancellationToken);
        _ = await security.ApproveAsync(approvalRequestV2.Id, validatedV2.Id, validatedV2.ChecksumSha256, digestV2, validatedV2.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddSeconds(13), TestContext.Current.CancellationToken);
        ConnectorVersionRecord publishedV2 = await connectorStore.PublishApprovedAsync(validatedV2.Id, digestV2, validatedV2.RowVersion, 1, approver.Id.ToString("D"), Guid.NewGuid(), now.AddSeconds(14), TestContext.Current.CancellationToken);
        Guid rollbackCorrelation = Guid.NewGuid();
        PostgresConnectorConfigurationStore faultedRollback = new(storePool.Value, new ThrowingFaultInjector("connector.rollback.after-state"));
        await Assert.ThrowsAsync<InjectedFailureException>(() => faultedRollback.RollbackAsync(connectorId, publishedV1.Version, publishedV2.RowVersion, approver.Id.ToString("D"), rollbackCorrelation, now.AddSeconds(15), TestContext.Current.CancellationToken));
        Assert.Equal("superseded", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV1.Id));
        Assert.Equal("published", await TextScalarAsync(adminPool.Value, "SELECT state FROM gateway.connector_version WHERE id=$1", publishedV2.Id));
        Assert.Equal(0L, await ScalarAsync(adminPool.Value, "SELECT count(*) FROM gateway.audit_event WHERE correlation_id=$1", rollbackCorrelation));
    }

    [Fact]
    public async Task M5_IT_DAT_Postgres_admin_sessions_are_hashed_expiring_and_revoked_on_privilege_change_when_configured()
    {
        string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(connectionString)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await using AdminPostgresDataSource adminPool = new(connectionString);
        await ApplyMigrationAsync();
        PostgresAdminSecurityStore security = new(adminPool);
        PostgresAdminSessionStore sessions = new(adminPool, security);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminExternalIdentity identity = new("https://session.example.test", "session-" + Guid.NewGuid().ToString("N"), "Session test", null);

        (string handle, AdminSessionRecord created) = await sessions.CreateAsync(identity, now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        string storedDigest = await TextScalarAsync(adminPool.Value, "SELECT encode(handle_sha256,'hex') FROM gateway.admin_session WHERE id=$1", created.Id);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(handle))), storedDigest, ignoreCase: true);
        Assert.DoesNotContain(handle, storedDigest, StringComparison.OrdinalIgnoreCase);
        AdminSessionRecord touched = Assert.IsType<AdminSessionRecord>(await sessions.ValidateAsync(handle, now.AddMinutes(10), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        Assert.Equal(now.AddMinutes(30), touched.IdleExpiresAt);

        _ = await security.AssignRoleAsync(created.Principal.Id, AdminRole.Viewer, null, created.Principal.Id, Guid.NewGuid(), now.AddMinutes(11), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(handle, now.AddMinutes(12), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));

        (string parallelHandle, AdminSessionRecord parallel) = await sessions.CreateAsync(identity, now.AddMinutes(13), TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        _ = await security.AssignRoleAsync(parallel.Principal.Id, AdminRole.Viewer, null, parallel.Principal.Id, Guid.NewGuid(), now.AddMinutes(14), TestContext.Current.CancellationToken);
        Assert.NotNull(await sessions.ValidateAsync(parallelHandle, now.AddMinutes(15), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        _ = await security.AssignRoleAsync(parallel.Principal.Id, AdminRole.ConnectorEditor, null, parallel.Principal.Id, Guid.NewGuid(), now.AddMinutes(16), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(parallelHandle, now.AddMinutes(17), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));

        (string idleHandle, AdminSessionRecord idle) = await sessions.CreateAsync(identity, now, TimeSpan.FromHours(8), TimeSpan.FromMinutes(1), TestContext.Current.CancellationToken);
        Assert.Null(await sessions.ValidateAsync(idleHandle, idle.IdleExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
        (string absoluteHandle, AdminSessionRecord absolute) = await sessions.CreateAsync(identity, now, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        Assert.Equal(absolute.AbsoluteExpiresAt, absolute.IdleExpiresAt);
        Assert.Null(await sessions.ValidateAsync(absoluteHandle, absolute.AbsoluteExpiresAt, TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken));
    }

    private static async Task WaitForVersionLockWaitAsync(NpgsqlDataSource dataSource, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 50; attempt++)
        {
            await using NpgsqlConnection observation = await dataSource.OpenConnectionAsync(cancellationToken);
            await using NpgsqlCommand command = new("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT state FROM gateway.connector_version%')", observation);
            if (await command.ExecuteScalarAsync(cancellationToken) is true) return;
            await Task.Delay(50, cancellationToken);
        }
        throw new TimeoutException("Binding mutation did not reach the connector-version lock barrier.");
    }

    private static async Task<TestProviderResources> RegisterTestResourcesAsync(PostgresConnectorConfigurationStore store, Guid environmentId, string connectorId, DateTimeOffset now)
    {
        string suffix = environmentId.ToString("N");
        string secretId = "api-" + suffix;
        string certificateId = "cert-" + suffix;
        CertificatePublicMetadata metadata = new(new string('A', 64), "CN=test-client", "CN=test-ca", now.AddDays(-1), now.AddDays(90), "ECDSA", 256, "1");
        ProviderResourceCatalogRecord secret = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", secretId, ProviderResourceType.Secret, "API key", environmentId, connectorId, "*", "synthetic://api-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now), TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord certificate = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", certificateId, ProviderResourceType.ClientCertificate, "Client certificate", environmentId, connectorId, "*", "synthetic://certificate", ProviderResourceStatus.Active, null, 0, 1, metadata, string.Empty, now), TestContext.Current.CancellationToken);
        return new(new(secret.ProviderId, secret.ResourceId, secret.ResourceType), new(certificate.ProviderId, certificate.ResourceId, certificate.ResourceType, PublicMetadataRevision: certificate.PublicMetadataRevision), Binding(secret), Binding(certificate));
    }

    private static ProviderResourceBinding Binding(ProviderResourceCatalogRecord value) => new(value.ProviderId, value.ProviderDisplayName, value.ProviderType, value.ResourceId, value.ResourceType, value.DisplayName, value.EnvironmentId, value.ConnectorScope, value.OperationScope, value.Version, value.Revision, value.PublicMetadataRevision, value.CertificateMetadata, value.ChecksumSha256);

    private sealed record TestProviderResources(ProviderResourceReference SecretReference, ProviderResourceReference CertificateReference, ProviderResourceBinding SecretBinding, ProviderResourceBinding CertificateBinding);

    private sealed class NeverReadSecretProvider : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException("Resolution must not dereference the secret value.");
    }

    private sealed class NeverRuntimeDependencies :
        ISecretValueProvider, IClientCertificateProvider, IHostResolver, IRestrictedTransport
    {
        public int Calls { get; private set; }

        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => Unexpected<string>();
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => Unexpected<X509Certificate2>();
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Unexpected<IPAddress[]>();
        public Task<ExternalResponse> SendAsync(
            HttpRequestMessage request,
            IReadOnlyList<IPAddress> approvedAddresses,
            X509Certificate2? clientCertificate,
            TimeSpan timeout,
            long maximumResponseBytes,
            CancellationToken cancellationToken) => Unexpected<ExternalResponse>();

        private Task<T> Unexpected<T>()
        {
            Calls++;
            return Task.FromException<T>(new InvalidOperationException("No post-authority dependency may be called."));
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, connection, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static GatewayAuditEvent Audit(Guid tenantId, Guid correlationId, string action, string targetId, DateTimeOffset now) =>
        new(Guid.NewGuid(), now, tenantId, "administrator", "fault-test", action, "test", targetId, correlationId, "success", "BGW-FAULT-TEST", new Dictionary<string, string>());

    private static async Task<long> ScalarAsync(NpgsqlDataSource dataSource, string sql, object value)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new(sql, connection); command.Parameters.AddWithValue(value);
        return Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string> TextScalarAsync(NpgsqlDataSource dataSource, string sql, object value)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new(sql, connection); command.Parameters.AddWithValue(value);
        return (string)(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
    }

    private static async Task AssertOwnedPaginationAsync<T>(
        Func<int, int, CancellationToken, Task<AdminPage<T>>> listPage,
        Func<T, Guid> selectId,
        Guid[] expectedOwnedIds,
        Guid foreignId,
        CancellationToken cancellationToken)
    {
        HashSet<Guid> owned = expectedOwnedIds.ToHashSet();
        Assert.DoesNotContain(foreignId, owned);
        IReadOnlyList<Guid> firstRead = await ListAllIdsIgnoringGlobalTotalAsync(listPage, selectId, cancellationToken);
        IReadOnlyList<Guid> repeatedRead = await ListAllIdsIgnoringGlobalTotalAsync(listPage, selectId, cancellationToken);
        Guid[] firstOwnedRead = firstRead.Where(owned.Contains).ToArray();
        Guid[] repeatedOwnedRead = repeatedRead.Where(owned.Contains).ToArray();
        Assert.Equal(expectedOwnedIds.Length, firstOwnedRead.Length);
        Assert.Equal(expectedOwnedIds.Length, firstOwnedRead.Distinct().Count());
        Assert.Equal(expectedOwnedIds, firstOwnedRead);
        Assert.Equal(firstOwnedRead, repeatedOwnedRead);
        Assert.Contains(foreignId, firstRead);

        int firstOwnedOffset = firstRead.ToList().FindIndex(id => id == expectedOwnedIds[0]);
        Assert.True(firstOwnedOffset >= 0);
        Assert.Equal(expectedOwnedIds, firstRead.Skip(firstOwnedOffset).Take(expectedOwnedIds.Length).ToArray());
        const int ownedPageSize = 25;
        for (int ownedOffset = 0; ownedOffset < expectedOwnedIds.Length; ownedOffset += ownedPageSize)
        {
            int limit = Math.Min(ownedPageSize, expectedOwnedIds.Length - ownedOffset);
            AdminPage<T> page = await listPage(firstOwnedOffset + ownedOffset, limit, cancellationToken);
            Assert.Equal(firstOwnedOffset + ownedOffset, page.Offset);
            Assert.Equal(limit, page.Limit);
            Assert.Equal(expectedOwnedIds.Skip(ownedOffset).Take(limit).ToArray(), page.Items.Select(selectId).ToArray());
        }

        AdminPage<T> empty = await listPage(int.MaxValue, 1, cancellationToken);
        Assert.Empty(empty.Items);
    }

    private static async Task<IReadOnlyList<Guid>> ListAllIdsIgnoringGlobalTotalAsync<T>(
        Func<int, int, CancellationToken, Task<AdminPage<T>>> listPage,
        Func<T, Guid> selectId,
        CancellationToken cancellationToken)
    {
        List<Guid> ids = [];
        int offset = 0;
        while (true)
        {
            AdminPage<T> page = await listPage(offset, 100, cancellationToken);
            Assert.Equal(offset, page.Offset);
            Assert.Equal(100, page.Limit);
            if (page.Items.Count == 0) break;
            ids.AddRange(page.Items.Select(selectId));
            offset += page.Items.Count;
        }
        return ids;
    }

    private static async Task ExecuteNonQueryAsync(string connectionString, string sql, CancellationToken cancellationToken, params object[] values)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using NpgsqlCommand command = new(sql, connection);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> HasTablePrivilegeAsync(NpgsqlConnection owner, string role, string table, string privilege)
    {
        await using NpgsqlCommand command = new("SELECT has_table_privilege($1,$2,$3)", owner);
        command.Parameters.AddWithValue(role);
        command.Parameters.AddWithValue(table);
        command.Parameters.AddWithValue(privilege);
        return Assert.IsType<bool>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task ExecuteAsRoleAsync(NpgsqlConnection owner, string role, Guid tenantId, string sql, params object[] values)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await SetRoleAndTenantAsync(owner, transaction, role, tenantId);
        await using NpgsqlCommand command = new(sql, owner, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        await transaction.CommitAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<T> ScalarAsRoleAsync<T>(NpgsqlConnection owner, string role, Guid tenantId, string sql, params object[] values)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await SetRoleAndTenantAsync(owner, transaction, role, tenantId);
        await using NpgsqlCommand command = new(sql, owner, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        object? result = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        return Assert.IsType<T>(result);
    }

    private static async Task<T> ScalarOwnerAsync<T>(NpgsqlConnection owner, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, owner);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        return Assert.IsType<T>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task ExecuteOwnerAsync(NpgsqlConnection owner, string sql, params object[] values)
    {
        await using NpgsqlCommand command = new(sql, owner);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task AssertRoleDeniedAsync(NpgsqlConnection owner, string role, Guid tenantId, string sql, params object[] values) =>
        await AssertSqlStateAsync(owner, role, tenantId, sql, PostgresErrorCodes.InsufficientPrivilege, values);

    private static async Task AssertRlsDeniedAsync(NpgsqlConnection owner, string role, Guid tenantId, string sql, params object[] values) =>
        await AssertSqlStateAsync(owner, role, tenantId, sql, PostgresErrorCodes.InsufficientPrivilege, values);

    private static async Task AssertSqlStateAsync(NpgsqlConnection owner, string role, Guid tenantId, string sql, string expectedSqlState, params object[] values)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await SetRoleAndTenantAsync(owner, transaction, role, tenantId);
        await using NpgsqlCommand command = new(sql, owner, transaction);
        foreach (object value in values) command.Parameters.AddWithValue(value);
        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        Assert.Equal(expectedSqlState, failure.SqlState);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
    }

    private static async Task SetRoleAndTenantAsync(NpgsqlConnection owner, NpgsqlTransaction transaction, string role, Guid tenantId)
    {
        Assert.True(role is "gateway_admin" or "gateway_runtime" or "gateway_readonly");
        await using (NpgsqlCommand setRole = new($"SET LOCAL ROLE {role}", owner, transaction))
            await setRole.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand setTenant = new("SELECT set_config('app.tenant_id',$1,true)", owner, transaction);
        setTenant.Parameters.AddWithValue(tenantId.ToString("D"));
        await setTenant.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_installation_search_preserves_tenant_and_context_filters()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection) || string.IsNullOrWhiteSpace(migrationConnection))
            Assert.Skip("The dedicated PostgreSQL gate must provide admin and migration connections.");
        await ApplyMigrationAsync();
        await using NpgsqlConnection owner = new(migrationConnection);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        EventPrivilegeFixture fixture = await CreateEventPrivilegeFixtureAsync(owner);
        try
        {
            await using AdminPostgresDataSource pool = new(adminConnection);
            PostgresAdminDirectoryStore directory = new(pool);
            AdminPage<InstallationRecord> result = await directory.ListInstallationsAsync(fixture.TenantA, 0, 1,
                TestContext.Current.CancellationToken, fixture.InstallationA.ToString("D").ToUpperInvariant(), fixture.ApplicationId, fixture.EnvironmentId);
            Assert.Equal(fixture.InstallationA, Assert.Single(result.Items).Id);
            Assert.Equal(1, result.Total);
            Assert.Empty((await directory.ListInstallationsAsync(fixture.TenantA, 0, 1,
                TestContext.Current.CancellationToken, fixture.InstallationB.ToString("D"))).Items);
            Assert.Empty((await directory.ListInstallationsAsync(fixture.TenantA, 0, 1,
                TestContext.Current.CancellationToken, "", Guid.NewGuid(), fixture.EnvironmentId)).Items);
            Assert.Empty((await directory.ListInstallationsAsync(fixture.TenantA, 0, 1,
                TestContext.Current.CancellationToken, "", fixture.ApplicationId, Guid.NewGuid())).Items);
            Assert.Equal(fixture.EnvironmentId, Assert.Single((await directory.ListEnvironmentsAsync(0, 1,
                TestContext.Current.CancellationToken, fixture.EnvironmentId.ToString("D"))).Items).Id);
        }
        finally { await CleanupEventPrivilegeFixtureAsync(owner, fixture); }
    }

    private static async Task<EventPrivilegeFixture> CreateEventPrivilegeFixtureAsync(NpgsqlConnection owner)
    {
        string marker = "append-" + Guid.NewGuid().ToString("N");
        EventPrivilegeFixture fixture = new(
            marker,
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid());
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.tenant(id,code,display_name,status,created_at) VALUES($1,$2,'Append tenant A','active',now()),($3,$4,'Append tenant B','active',now())", fixture.TenantA, "ta-" + marker, fixture.TenantB, "tb-" + marker);
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.application(id,code,display_name,status,minimum_broker_version,created_at) VALUES($1,$2,'Append application','active','1.0.0',now())", fixture.ApplicationId, "app-" + marker);
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.environment(id,code,display_name,production_controls) VALUES($1,$2,'Append environment',false)", fixture.EnvironmentId, "env-" + marker[..20]);
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.installation(id,tenant_id,application_id,environment_id,status,created_at) VALUES($1,$2,$3,$4,'active',now()),($5,$6,$3,$4,'active',now())", fixture.InstallationA, fixture.TenantA, fixture.ApplicationId, fixture.EnvironmentId, fixture.InstallationB, fixture.TenantB);
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted) VALUES($1,now(),$2,'administrator','append-only-test','security.append-only','audit_event',$3,$4,'success','AUDIT-ORIGINAL','{}'::jsonb)", fixture.AuditId, fixture.TenantA, fixture.Marker, Guid.NewGuid());
        await ExecuteAsync(owner, transaction, "INSERT INTO gateway.invocation_event(id,occurred_at,tenant_id,installation_id,connector_id,operation_id,correlation_id,outcome,duration_ms,payload_bytes) VALUES($1,now(),$2,$3,$4,$5,$6,'success',1,0)", fixture.InvocationId, fixture.TenantA, fixture.InstallationA, fixture.ConnectorId, fixture.Marker, Guid.NewGuid());
        await transaction.CommitAsync(TestContext.Current.CancellationToken);
        return fixture;
    }

    private static async Task AssertEventRowsUnchangedAsync(NpgsqlConnection owner, EventPrivilegeFixture fixture)
    {
        Assert.Equal("AUDIT-ORIGINAL", await ScalarOwnerAsync<string>(owner, "SELECT reason_code FROM gateway.audit_event WHERE id=$1", fixture.AuditId));
        Assert.Equal("success", await ScalarOwnerAsync<string>(owner, "SELECT outcome FROM gateway.invocation_event WHERE id=$1", fixture.InvocationId));
    }

    private static async Task CleanupEventPrivilegeFixtureAsync(NpgsqlConnection owner, EventPrivilegeFixture fixture)
    {
        await using NpgsqlTransaction transaction = await owner.BeginTransactionAsync(CancellationToken.None);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.audit_event WHERE target_id=$1", fixture.Marker);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.invocation_event WHERE operation_id=$1", fixture.Marker);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.installation WHERE id IN ($1,$2)", fixture.InstallationA, fixture.InstallationB);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.application WHERE id=$1", fixture.ApplicationId);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.environment WHERE id=$1", fixture.EnvironmentId);
        await ExecuteAsync(owner, transaction, "DELETE FROM gateway.tenant WHERE id IN ($1,$2)", fixture.TenantA, fixture.TenantB);
        await transaction.CommitAsync(CancellationToken.None);
    }

    private sealed record EventPrivilegeFixture(
        string Marker,
        Guid TenantA,
        Guid TenantB,
        Guid ApplicationId,
        Guid EnvironmentId,
        Guid InstallationA,
        Guid InstallationB,
        Guid ConnectorId,
        Guid AuditId,
        Guid InvocationId);

    private static async Task<(uint Oid, string Definition)> ReadDiagnosticCodeConstraintAsync(string connectionString)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new(
            "SELECT oid,pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='ck_audit_failure_diagnostic_codes_allowlisted' AND conrelid='gateway.audit_event'::regclass",
            connection);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        return (reader.GetFieldValue<uint>(0), reader.GetString(1));
    }

    private static async Task AssertDiagnosticCodeConstraintRejectsAsync(string connectionString, string value, bool local)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        string phase = local ? "LOCAL_RESPONSE_MAPPING_FAILURE" : "UPSTREAM_HTTP_RESPONSE";
        int status = local ? 200 : 400;
        string category = local ? "SUCCESS" : "CLIENT_ERROR";
        await using NpgsqlCommand command = new(
            "INSERT INTO gateway.audit_event(id,occurred_at,tenant_id,actor_type,actor_id,action,target_type,target_id,correlation_id,outcome,reason_code,metadata_redacted,failure_phase,upstream_status,status_category,safe_upstream_code,local_safe_code) VALUES($1,now(),NULL,'installation','bounded-test','operation.invoke','operation','fse2/create',$2,'failure','BGW-EGRESS-UPSTREAM-REJECTED','{}'::jsonb,$3,$4,$5,$6,$7)",
            connection);
        command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(Guid.NewGuid());
        command.Parameters.AddWithValue(phase);
        command.Parameters.AddWithValue(status);
        command.Parameters.AddWithValue(category);
        command.Parameters.AddWithValue(local ? DBNull.Value : value);
        command.Parameters.AddWithValue(local ? value : DBNull.Value);
        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() =>
            command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
        Assert.Equal(PostgresErrorCodes.CheckViolation, failure.SqlState);
        Assert.Equal("ck_audit_failure_diagnostic_codes_allowlisted", failure.ConstraintName);
    }

    internal static async Task ApplyMigrationAsync()
    {
        string connectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION")
            ?? Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION")
            ?? throw new InvalidOperationException("PostgreSQL migration connection is not configured.");
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await ApplyMigrationAsync(connection);
    }

    private static async Task ApplyMigrationAsync(NpgsqlConnection connection)
    {
        string directory = Path.Combine(FindRepositoryRoot(), "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations");
        foreach (string path in Directory.GetFiles(directory, "*.sql").Order(StringComparer.Ordinal))
        {
            string migration = await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken);
            await using NpgsqlCommand command = new(migration, connection);
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }


    private sealed class TestClock(DateTimeOffset value) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = value;
    }

    private sealed class ThrowingFaultInjector(string point) : IAdminTransactionFaultInjector
    {
        public void Check(string boundary)
        {
            if (string.Equals(boundary, point, StringComparison.Ordinal)) throw new InjectedFailureException(boundary);
        }
    }

    private sealed class InjectedFailureException(string boundary) : Exception(boundary);
}
