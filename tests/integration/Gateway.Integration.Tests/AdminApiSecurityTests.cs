using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.Http.Json;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public enum AdminRateLimitTestPolicyClass
{
    Auth,
    Api
}

public enum AdminRateLimitTestPrincipalKind
{
    RemoteIp,
    AuthenticatedSubject,
    Unavailable
}

public sealed record AdminRateLimitTestObservation(
    long Sequence,
    long LimiterInstanceId,
    long WindowGeneration,
    AdminRateLimitTestPolicyClass PolicyClass,
    AdminRateLimitTestPrincipalKind PrincipalKind,
    string PartitionFingerprint,
    bool Acquired);

public sealed class BoundedAdminRateLimitTestProbe
{
    private const int MaximumObservations = 4096;
    private readonly object sync = new();
    private readonly Queue<AdminRateLimitTestObservation> observations = [];
    private readonly ProbeObserver observer;
    private readonly TimeProvider? observationTimeProvider;

    public BoundedAdminRateLimitTestProbe(TimeProvider? observationTimeProvider = null)
    {
        this.observationTimeProvider = observationTimeProvider;
        observer = new(this);
    }

    public PartitionedRateLimiter<HttpContext> CreateGlobalLimiter() =>
        observationTimeProvider is null
            ? AdminRateLimiting.CreateGlobalLimiter(observer)
            : AdminRateLimiting.CreateGlobalLimiter(observer, observationTimeProvider);

    public PartitionedRateLimiter<HttpContext> CreateGlobalLimiter(
        int authPermitLimit,
        int apiPermitLimit,
        TimeSpan window) =>
        AdminRateLimiting.CreateGlobalLimiter(
            authPermitLimit,
            apiPermitLimit,
            window,
            observer: observer,
            observationTimeProvider: observationTimeProvider);

    public AdminRateLimitTestObservation[] Snapshot()
    {
        lock (sync) return observations.ToArray();
    }

    private void Observe(AdminRateLimitObservation observation)
    {
        lock (sync)
        {
            if (observations.Count == MaximumObservations) _ = observations.Dequeue();
            observations.Enqueue(new(
                observation.Sequence,
                observation.LimiterInstanceId,
                observation.WindowGeneration,
                observation.PolicyClass switch
                {
                    AdminRateLimitPolicyClass.Auth => AdminRateLimitTestPolicyClass.Auth,
                    AdminRateLimitPolicyClass.Api => AdminRateLimitTestPolicyClass.Api,
                    _ => throw new InvalidOperationException("ADMIN_RATE_LIMIT_TEST_POLICY_CLASS_INVALID")
                },
                observation.PrincipalKind switch
                {
                    AdminRateLimitPrincipalKind.RemoteIp => AdminRateLimitTestPrincipalKind.RemoteIp,
                    AdminRateLimitPrincipalKind.AuthenticatedSubject => AdminRateLimitTestPrincipalKind.AuthenticatedSubject,
                    AdminRateLimitPrincipalKind.Unavailable => AdminRateLimitTestPrincipalKind.Unavailable,
                    _ => throw new InvalidOperationException("ADMIN_RATE_LIMIT_TEST_PRINCIPAL_KIND_INVALID")
                },
                observation.PartitionFingerprint,
                observation.Acquired));
        }
    }

    private sealed class ProbeObserver(BoundedAdminRateLimitTestProbe owner) : IAdminRateLimitObserver
    {
        public void Observe(AdminRateLimitObservation observation) => owner.Observe(observation);
    }
}

public sealed class AdminApiSecurityTests
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task FSE2_ADMIN_AUDIT_SecurityAdministrator_reads_bounded_failure_diagnostics()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await SeedFailureAuditAsync(factory, TestContext.Current.CancellationToken);

        using HttpResponseMessage response = await client.GetAsync($"/admin/api/v1/audit?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement audit = Assert.Single(document.RootElement.GetProperty("items").EnumerateArray());
        JsonElement diagnostics = audit.GetProperty("failureDiagnostics");

        Assert.Equal("UPSTREAM_HTTP_RESPONSE", diagnostics.GetProperty("failurePhase").GetString());
        Assert.Equal(400, diagnostics.GetProperty("upstreamStatus").GetInt32());
        Assert.Equal("CLIENT_ERROR", diagnostics.GetProperty("statusCategory").GetString());
        Assert.Equal("syntax", diagnostics.GetProperty("safeUpstreamCode").GetString());
        Assert.Equal(JsonValueKind.Null, diagnostics.GetProperty("localSafeCode").ValueKind);
        Assert.Equal(5, diagnostics.EnumerateObject().Count());
        foreach (string forbidden in new[] { "metadata", "actorId", "raw", "header", "authorization", "jwt", "cookie", "certificate", "exception", "stack", "hostname" })
            Assert.DoesNotContain(forbidden, body, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("viewer")]
    [InlineData("operator")]
    [InlineData("editor")]
    [InlineData("approver")]
    public async Task FSE2_ADMIN_AUDIT_non_security_roles_cannot_read_failure_diagnostics(string user)
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient administrator = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(administrator, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await SeedFailureAuditAsync(factory, TestContext.Current.CancellationToken);
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(client, user, TestContext.Current.CancellationToken);

        using HttpResponseMessage response = await client.GetAsync($"/admin/api/v1/audit?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.DoesNotContain("failureDiagnostics", body, StringComparison.Ordinal);
        Assert.DoesNotContain("UPSTREAM_HTTP_RESPONSE", body, StringComparison.Ordinal);
        Assert.DoesNotContain("syntax", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADMIN_AUDIT_EXPORT_uses_interval_keyset_cursor_and_excludes_later_appends()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await SeedExportAuditAsync(factory, TestContext.Current.CancellationToken);
        DateTimeOffset from = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);
        DateTimeOffset to = new(2026, 9, 10, 12, 10, 0, TimeSpan.Zero);

        using HttpResponseMessage first = await client.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&fromUtc={Uri.EscapeDataString(from.ToString("O"))}&toUtc={Uri.EscapeDataString(to.ToString("O"))}&limit=2", TestContext.Current.CancellationToken);
        string firstBody = await first.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        first.EnsureSuccessStatusCode();
        using JsonDocument firstDocument = JsonDocument.Parse(firstBody);
        JsonElement[] firstItems = firstDocument.RootElement.GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal(2, firstItems.Length);
        Assert.Equal("operation.invoke", firstItems[0].GetProperty("action").GetString());
        Assert.Equal("admin", firstItems[0].GetProperty("actorType").GetString());
        Assert.Equal("actor-newer", firstItems[0].GetProperty("actorId").GetString());
        Assert.True(firstDocument.RootElement.GetProperty("partial").GetBoolean());
        string continuation = firstDocument.RootElement.GetProperty("continuation").GetString()!;
        using HttpResponseMessage changedBounds = await client.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&fromUtc={Uri.EscapeDataString(from.AddMinutes(-1).ToString("O"))}&toUtc={Uri.EscapeDataString(to.ToString("O"))}&cursor={Uri.EscapeDataString(continuation)}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, changedBounds.StatusCode);
        JsonElement changedBoundsProblem = await changedBounds.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("BGW-ADMIN-AUDIT-EXPORT-CURSOR", changedBoundsProblem.GetProperty("code").GetString());
        Assert.DoesNotContain("metadata", firstBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw-secret-canary", firstBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("other-tenant", firstBody, StringComparison.Ordinal);

        IAdminGatewayRegistry registry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        await registry.AppendAuditAsync(new(Guid.NewGuid(), to.AddSeconds(1), tenantId, "admin", "actor-after-watermark", "tenant.update", "tenant", tenantId.ToString("D"), Guid.NewGuid(), "success", "BGW-AFTER-WATERMARK", new Dictionary<string, string>()), TestContext.Current.CancellationToken);

        using HttpResponseMessage second = await client.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&fromUtc={Uri.EscapeDataString(from.ToString("O"))}&toUtc={Uri.EscapeDataString(to.ToString("O"))}&limit=2&cursor={Uri.EscapeDataString(continuation)}", TestContext.Current.CancellationToken);
        second.EnsureSuccessStatusCode();
        string secondBody = await second.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument secondDocument = JsonDocument.Parse(secondBody);
        JsonElement[] secondItems = secondDocument.RootElement.GetProperty("items").EnumerateArray().ToArray();
        Assert.Single(secondItems);
        Assert.Equal("tenant.create", secondItems[0].GetProperty("action").GetString());
        Assert.False(secondDocument.RootElement.GetProperty("partial").GetBoolean());
        Assert.Equal(JsonValueKind.Null, secondDocument.RootElement.GetProperty("continuation").ValueKind);
        Assert.DoesNotContain("actor-after-watermark", secondBody, StringComparison.Ordinal);
        Assert.DoesNotContain("other-tenant", secondBody, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=1001")]
    [InlineData("fromUtc=2026-09-10T12%3A10%3A00Z&toUtc=2026-09-10T12%3A00%3A00Z&limit=2")]
    [InlineData("fromUtc=2026-09-10T12%3A00%3A00%2B02%3A00&toUtc=2026-09-10T12%3A10%3A00Z&limit=2")]
    [InlineData("cursor=not-a-cursor")]
    public async Task ADMIN_AUDIT_EXPORT_rejects_invalid_bounds_limits_and_cursor(string query)
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await SeedExportAuditAsync(factory, TestContext.Current.CancellationToken);
        string interval = query.Contains("fromUtc=", StringComparison.Ordinal)
            ? query
            : "fromUtc=2026-09-10T12%3A00%3A00.0000000Z&toUtc=2026-09-10T12%3A10%3A00.0000000Z&" + query;

        using HttpResponseMessage response = await client.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&{interval}", TestContext.Current.CancellationToken);
        JsonElement problem = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        string code = problem.GetProperty("code").GetString() ?? string.Empty;
        Assert.True(code is "BGW-ADMIN-AUDIT-EXPORT" or "BGW-ADMIN-AUDIT-EXPORT-CURSOR");
    }

    [Theory]
    [InlineData("viewer", false)]
    [InlineData("operator", false)]
    [InlineData("security-admin", true)]
    public async Task ADMIN_AUDIT_EXPORT_limits_diagnostics_to_security_role(string user, bool diagnostics)
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient administrator = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(administrator, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await SeedFailureAuditAsync(factory, TestContext.Current.CancellationToken);
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(client, user, TestContext.Current.CancellationToken);

        using HttpResponseMessage response = await client.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&fromUtc=2000-01-01T00%3A00%3A00.0000000Z&toUtc=2100-01-01T00%3A00%3A00.0000000Z", TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement item = Assert.Single(document.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal(diagnostics, item.TryGetProperty("failureDiagnostics", out _));
        Assert.Equal(diagnostics, body.Contains("syntax", StringComparison.Ordinal));
    }

    private static async Task<Guid> SeedFailureAuditAsync(AdminDevelopmentFactory factory, CancellationToken cancellationToken)
    {
        Guid tenantId = Guid.NewGuid();
        IAdminGatewayRegistry registry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        await registry.AddTenantAsync(new(tenantId, "diag-" + tenantId.ToString("N"), "Diagnostics tenant", TenantStatus.Active, DateTimeOffset.UtcNow), cancellationToken);
        await registry.AppendAuditAsync(new(
            Guid.NewGuid(), DateTimeOffset.UtcNow, tenantId, "installation", Guid.NewGuid().ToString("D"),
            "operation.invoke", "operation", "fse2/create", Guid.NewGuid(), "failure",
            "BGW-EGRESS-UPSTREAM-REJECTED", new Dictionary<string, string>
            {
                ["connectorVersion"] = "1.0.0",
                ["callerKind"] = "Direct"
            },
            GatewayAuditFailureDiagnostics.Create(
                GatewayAuditFailurePhase.UpstreamHttpResponse,
                400,
                GatewayAuditStatusCategory.ClientError,
                "syntax",
                null)), cancellationToken);
        return tenantId;
    }

    private static async Task<Guid> SeedExportAuditAsync(AdminDevelopmentFactory factory, CancellationToken cancellationToken)
    {
        Guid tenantId = Guid.NewGuid();
        IAdminGatewayRegistry registry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        await registry.AddTenantAsync(new(tenantId, "export-" + tenantId.ToString("N"), "Export tenant", TenantStatus.Active, new DateTimeOffset(2026, 9, 10, 11, 59, 0, TimeSpan.Zero)), cancellationToken);
        IReadOnlyList<(DateTimeOffset OccurredAt, string Actor, string Action, string Reason)> events =
        [
            (new DateTimeOffset(2026, 9, 10, 12, 5, 0, TimeSpan.Zero), "actor-newer", "operation.invoke", "BGW-OPERATION-OK"),
            (new DateTimeOffset(2026, 9, 10, 12, 3, 0, TimeSpan.Zero), "actor-middle", "grant.create", "BGW-ADMIN-ACTION"),
            (new DateTimeOffset(2026, 9, 10, 12, 1, 0, TimeSpan.Zero), "actor-older", "tenant.create", "BGW-ADMIN-ACTION"),
            (new DateTimeOffset(2026, 9, 10, 11, 59, 0, TimeSpan.Zero), "actor-before", "tenant.disable", "BGW-BEFORE-INTERVAL")
        ];
        foreach ((DateTimeOffset occurredAt, string actor, string action, string reason) in events)
            await registry.AppendAuditAsync(new(Guid.NewGuid(), occurredAt, tenantId, "admin", actor, action, "tenant", tenantId.ToString("D"), Guid.NewGuid(), "success", reason, new Dictionary<string, string> { ["canary"] = "raw-secret-canary" }), cancellationToken);
        await registry.AppendAuditAsync(new(Guid.NewGuid(), new DateTimeOffset(2026, 9, 10, 12, 4, 0, TimeSpan.Zero), Guid.NewGuid(), "admin", "other-tenant", "tenant.create", "tenant", "other", Guid.NewGuid(), "success", "BGW-OTHER-TENANT", new Dictionary<string, string>()), cancellationToken);
        return tenantId;
    }

    internal static async Task RunPostgreSqlTenantSearchAsync()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection) || string.IsNullOrWhiteSpace(migrationConnection))
            Assert.Skip("The 10,000-tenant API search requires the dedicated PostgreSQL 18 gate.");
        await using PostgresRuntimeRoleLease runtimeRole = await PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);
        await using WebApplicationFactory<Program> factory = new AdminDevelopmentFactory().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:GatewayDatabase", runtimeRole.ConnectionString);
            builder.UseSetting("ConnectionStrings:GatewayAdminDatabase", adminConnection);
        });
        await using NpgsqlConnection owner = new(migrationConnection);
        await owner.OpenAsync(TestContext.Current.CancellationToken);
        string prefix = "search-" + Guid.NewGuid().ToString("N");
        try
        {
            await using NpgsqlCommand seed = new("INSERT INTO gateway.tenant(id,code,display_name,status,created_at) SELECT gen_random_uuid(), @prefix || '-' || lpad(n::text,5,'0'), CASE WHEN n>=9998 THEN @prefix || ' shared' ELSE 'Tenant ' || n::text END, 'active', now() FROM generate_series(0,9999) n", owner);
            seed.Parameters.AddWithValue("prefix", prefix);
            Assert.Equal(10000, await seed.ExecuteNonQueryAsync(TestContext.Current.CancellationToken));
            using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
            using HttpResponseMessage anonymous = await client.GetAsync("/admin/api/v1/tenants?limit=50", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            _ = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
            async Task<AdminPage<TenantRecord>> Search(string filter, int offset = 0, int limit = 50) =>
                await client.GetFromJsonAsync<AdminPage<TenantRecord>>($"/admin/api/v1/tenants?filter={Uri.EscapeDataString(filter)}&offset={offset}&limit={limit}", WireJson, TestContext.Current.CancellationToken)
                ?? throw new InvalidOperationException("Missing tenant page.");
            AdminPage<TenantRecord> first = await Search(prefix);
            Assert.Equal(10000, first.Total);
            Assert.Equal(50, first.Items.Count);
            AdminPage<TenantRecord> last = await Search(" " + prefix.ToUpperInvariant() + "-09999 ");
            Assert.Equal(1, last.Total);
            TenantRecord selected = Assert.Single(last.Items);
            Assert.Equal(prefix + "-09999", selected.Code);
            AdminPage<TenantRecord> duplicateA = await Search(prefix + " shared", 0, 1);
            AdminPage<TenantRecord> duplicateB = await Search(prefix + " shared", 1, 1);
            Assert.Equal(2, duplicateA.Total);
            Assert.NotEqual(Assert.Single(duplicateA.Items).Id, Assert.Single(duplicateB.Items).Id);
            Assert.Equal(selected.Id, Assert.Single(duplicateB.Items).Id);
            Assert.Empty((await Search(prefix + "-absent")).Items);
            Assert.Empty((await Search("%_' OR 1=1 --")).Items);
            TenantRecord? resumed = await client.GetFromJsonAsync<TenantRecord>($"/admin/api/v1/tenants/{selected.Id:D}", WireJson, TestContext.Current.CancellationToken);
            Assert.Equal(selected.Id, resumed?.Id);
            using HttpResponseMessage oversized = await client.GetAsync("/admin/api/v1/tenants?limit=101", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
        }
        finally
        {
            await using NpgsqlCommand cleanup = new("DELETE FROM gateway.tenant WHERE starts_with(code,@prefix)", owner);
            cleanup.Parameters.AddWithValue("prefix", prefix + "-");
            await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    internal static async Task RunPostgreSqlApprovalPublishAntiExfiltrationAsync()
    {
        string? adminConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string? migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnectionString) || string.IsNullOrWhiteSpace(migrationConnectionString))
            Assert.Skip("The definitive anti-exfiltration scenario requires the dedicated PostgreSQL 18 gate.");
        await using PostgresRuntimeRoleLease runtimeRole = await PostgresRuntimeRoleLease.CreateAsync(adminConnectionString, migrationConnectionString, TestContext.Current.CancellationToken);
        await using AntiExfiltrationFactory factory = new(runtimeRole.ConnectionString, adminConnectionString);
        using HttpClient editor = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpClient approver = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string editorCsrf = await LoginAsync(editor, "security-admin", TestContext.Current.CancellationToken);
        string canary = "m5-e2e-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        string syntheticConnectionString = $"Host=db.invalid;Password={Convert.ToHexString(RandomNumberGenerator.GetBytes(24))}";
        using CertificateSet certificates = CertificateSet.Create("approved.vendor.example", DateTimeOffset.UtcNow.AddDays(5));
        X509Certificate2 created = certificates.ClientCertificate;
        byte[] pfx = created.Export(X509ContentType.Pkcs12);
        string privatePem = certificates.ClientPrivateKeyPem;
        string pfxBase64 = Convert.ToBase64String(pfx);
        CertificatePublicMetadata publicMetadata = new(Convert.ToHexString(SHA256.HashData(created.RawData)), created.Subject, created.Issuer, created.NotBefore, created.NotAfter, "RSA", 2048, created.SerialNumber);

        Guid environmentId = Guid.NewGuid(); Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
        IAdminGatewayRegistry adminRegistry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        IGatewayRegistry registry = factory.Services.GetRequiredService<IGatewayRegistry>();
        await adminRegistry.AddEnvironmentAsync(new(environmentId, "m5-e2e-" + environmentId.ToString("N")[..12], "M5 E2E", false), TestContext.Current.CancellationToken);
        await adminRegistry.AddTenantAsync(new(tenantId, "m5-e2e-" + tenantId.ToString("N")[..12], "M5 E2E", TenantStatus.Active, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        await adminRegistry.AddApplicationAsync(new(applicationId, "m5-e2e-" + applicationId.ToString("N")[..12], "M5 E2E", ApplicationStatus.Active, "3.0.0", null, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        await adminRegistry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);

        ConnectorVersionResource version = await ImportAndValidateSampleAsync(editor, editorCsrf, TestContext.Current.CancellationToken);
        await adminRegistry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, version.ConnectorId, "submit", true, DateTimeOffset.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        ProviderResourceCatalogRecord secret = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "instrumented", "Instrumented provider", "synthetic", "api-key", ProviderResourceType.Secret, "Vendor API key", environmentId, version.ConnectorId, "submit", "instrumented://api-key", ProviderResourceStatus.Active, "api-v1", 0, null, null, string.Empty, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord certificateResource = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "instrumented", "Instrumented provider", "synthetic", "certificate", ProviderResourceType.ClientCertificate, "Vendor certificate", environmentId, version.ConnectorId, "submit", "instrumented://certificate", ProviderResourceStatus.Active, "cert-resource-v1", 0, 1, publicMetadata, string.Empty, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        string exactProviderPath = $"/admin/api/v1/provider-resources:resolve?environmentId={environmentId:D}&resourceType=ClientCertificate&providerId=instrumented&resourceId=certificate&version=cert-resource-v1&revision={certificateResource.Revision}&publicMetadataRevision=1";
        using (HttpResponseMessage exactProvider = await editor.GetAsync(exactProviderPath, TestContext.Current.CancellationToken))
        {
            exactProvider.EnsureSuccessStatusCode();
            JsonElement exact = await exactProvider.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(certificateResource.Id, exact.GetProperty("id").GetGuid());
            Assert.False(exact.TryGetProperty("providerReference", out _));
        }
        using (HttpResponseMessage wrongProviderType = await editor.GetAsync(exactProviderPath.Replace("ClientCertificate", "Secret", StringComparison.Ordinal), TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.NotFound, wrongProviderType.StatusCode);
            JsonElement problem = await wrongProviderType.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal("BGW-PROVIDER-RESOURCE-NOT-FOUND", problem.GetProperty("code").GetString());
        }
        string syntheticPassword = "synthetic-password-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        string[] hostileResourceIds = [canary, syntheticPassword, privatePem, pfxBase64, syntheticConnectionString, "https://attacker.example/credential", "missing-resource"];
        foreach (string hostileResourceId in hostileResourceIds)
        {
            ProviderResourceReference hostileReference = new("instrumented", hostileResourceId, ProviderResourceType.Secret, "api-v1");
            try
            {
                ProviderResourceReferenceValidator.Validate(hostileReference);
                GatewayException absent = await Assert.ThrowsAsync<GatewayException>(() => store.ResolveProviderResourceAsync(hostileReference, environmentId, version.ConnectorId, ["submit"], TestContext.Current.CancellationToken));
                Assert.Equal("BGW-PROVIDER-RESOURCE-NOT-FOUND", absent.Code);
            }
            catch (GatewayException denied)
            {
                Assert.Equal("BGW-PROVIDER-RESOURCE-REFERENCE-DENIED", denied.Code);
            }
        }

        await using RealVendorMock vendor = await RealVendorMock.StartAsync(certificates, canary, publicMetadata.FingerprintSha256, TestContext.Current.CancellationToken);
        await using RealVendorMock attackerVendor = await RealVendorMock.StartAsync(certificates, "synthetic-never-approved", publicMetadata.FingerprintSha256, TestContext.Current.CancellationToken);
        object binding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = $"https://approved.vendor.example:{vendor.Port}/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "instrumented", resourceId = "api-key", resourceType = "Secret", version = "api-v1" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "instrumented", resourceId = "certificate", resourceType = "ClientCertificate", version = "cert-resource-v1", publicMetadataRevision = 1 } }
        };
        using (HttpResponseMessage response = await PutBindingAsync(editor, version.ConnectorId, binding, editorCsrf, null)) response.EnsureSuccessStatusCode();

        InstrumentedProvider provider = new(canary, pfx);
        CountingRestrictedTransport transport = new(new SystemRestrictedTransport(new X509Certificate2Collection(certificates.RootCertificate), Convert.ToHexString(SHA256.HashData(certificates.ServerCertificate.RawData))));
        PublishedConnectorCatalog runtimeCatalog = new(store, new ConnectorDefinitionValidator(), new SystemGatewayClock(), TimeSpan.FromMinutes(5));
        RestrictedEgressService runtime = new(registry, runtimeCatalog, provider, provider, new LoopbackResolver(), transport, new SystemGatewayClock(), new ExactLoopbackAllowance("approved.vendor.example"));
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, created.RawData, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), "3.0.0", null);
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{\"synthetic\":true}"), Guid.NewGuid());

        await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken));
        Assert.Equal(0, provider.SecretInvocations); Assert.Equal(0, transport.Invocations); Assert.Equal(0, vendor.Requests); Assert.Equal(0, attackerVendor.Requests);

        using HttpRequestMessage requestApproval = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-requests");
        requestApproval.Headers.Add("X-CSRF-TOKEN", editorCsrf);
        using HttpResponseMessage requested = await editor.SendAsync(requestApproval, TestContext.Current.CancellationToken); requested.EnsureSuccessStatusCode();
        JsonElement approvalRequest = await requested.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        string approvalId = approvalRequest.GetProperty("id").GetString()!;
        using HttpResponseMessage reviewResponse = await editor.GetAsync($"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-review", TestContext.Current.CancellationToken); reviewResponse.EnsureSuccessStatusCode();
        string reviewJson = await reviewResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument review = JsonDocument.Parse(reviewJson);
        string digest = review.RootElement.GetProperty("digestSha256").GetString()!;
        JsonElement certificateReview = review.RootElement.GetProperty("artifact").GetProperty("operations")[0].GetProperty("certificateBindings")[0];
        Assert.Equal("cert-resource-v1", certificateReview.GetProperty("resourceVersion").GetString());
        Assert.Equal(created.SerialNumber, certificateReview.GetProperty("certificateVersion").GetString());
        Assert.Equal(1, certificateReview.GetProperty("publicMetadataRevision").GetInt64());
        Assert.DoesNotContain(canary, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(privatePem, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(pfxBase64, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(syntheticConnectionString, reviewJson, StringComparison.Ordinal);

        string approverCsrf = await LoginAsync(approver, "approver", TestContext.Current.CancellationToken);
        using HttpRequestMessage approve = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId = approvalId, expectedDigestSha256 = digest }) };
        approve.Headers.Add("X-CSRF-TOKEN", approverCsrf);
        using (HttpResponseMessage approved = await approver.SendAsync(approve, TestContext.Current.CancellationToken)) approved.EnsureSuccessStatusCode();
        await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken));
        Assert.Equal(0, provider.SecretInvocations); Assert.Equal(0, transport.Invocations); Assert.Equal(0, vendor.Requests); Assert.Equal(0, attackerVendor.Requests);

        ConnectorVersionRecord beforeWrongPublisher = (await store.GetVersionAsync(version.ConnectorId, version.Version, TestContext.Current.CancellationToken))!;
        ConnectorSummary summaryBeforeWrongPublisher = Assert.Single(await store.ListConnectorsAsync(TestContext.Current.CancellationToken), value => value.ConnectorId == version.ConnectorId);
        using HttpRequestMessage wrongPublisher = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}:publish") { Content = JsonContent.Create(new { expectedRowVersion = version.RowVersion, expectedPublicationRevision = 0 }) };
        wrongPublisher.Headers.Add("X-CSRF-TOKEN", editorCsrf); wrongPublisher.Headers.TryAddWithoutValidation("If-Match", $"\"{version.RowVersion}\"");
        using (HttpResponseMessage denied = await editor.SendAsync(wrongPublisher, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Conflict, denied.StatusCode);
            JsonElement problem = await denied.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal("BGW-ADMIN-APPROVAL-REQUIRED", problem.GetProperty("code").GetString());
        }
        ConnectorVersionRecord afterWrongPublisher = (await store.GetVersionAsync(version.ConnectorId, version.Version, TestContext.Current.CancellationToken))!;
        ConnectorSummary summaryAfterWrongPublisher = Assert.Single(await store.ListConnectorsAsync(TestContext.Current.CancellationToken), value => value.ConnectorId == version.ConnectorId);
        Assert.Equal(beforeWrongPublisher.State, afterWrongPublisher.State);
        Assert.Equal(beforeWrongPublisher.RowVersion, afterWrongPublisher.RowVersion);
        Assert.Equal(summaryBeforeWrongPublisher.PublicationRevision, summaryAfterWrongPublisher.PublicationRevision);
        Assert.Equal(summaryBeforeWrongPublisher.PublishedVersion, summaryAfterWrongPublisher.PublishedVersion);

        using HttpRequestMessage publish = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}:publish") { Content = JsonContent.Create(new { expectedRowVersion = version.RowVersion, expectedPublicationRevision = 0 }) };
        publish.Headers.Add("X-CSRF-TOKEN", approverCsrf); publish.Headers.TryAddWithoutValidation("If-Match", $"\"{version.RowVersion}\"");
        using (HttpResponseMessage published = await approver.SendAsync(publish, TestContext.Current.CancellationToken))
            Assert.True(published.IsSuccessStatusCode, $"{published.StatusCode}: {await published.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        GatewayInvokeResponse result = await runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.SecretInvocations); Assert.Equal(1, provider.CertificateInvocations); Assert.Equal(1, transport.Invocations);
        Assert.Equal(1, vendor.Requests); Assert.Equal(0, attackerVendor.Requests); Assert.True(vendor.ApiKeyMatched); Assert.True(vendor.ClientCertificateMatched); Assert.Equal(invocation.CorrelationId, vendor.CorrelationId);
        Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(result.Result.Data)), StringComparison.Ordinal);
        Assert.DoesNotContain(canary, JsonSerializer.Serialize(result), StringComparison.Ordinal);

        int secretCount = provider.SecretInvocations; int transportCount = transport.Invocations;
        GatewayException attacker = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version.ConnectorId, "attacker-operation", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHZ-OPERATION-DENIED", attacker.Code); Assert.Equal(secretCount, provider.SecretInvocations); Assert.Equal(transportCount, transport.Invocations); Assert.Equal(1, vendor.Requests); Assert.Equal(0, attackerVendor.Requests);

        ProviderResourceCatalogRecord rotatedResource = await store.RegisterProviderResourceAsync(secret with { Id = Guid.NewGuid(), ProviderReference = "instrumented://rotated", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = DateTimeOffset.UtcNow.AddSeconds(1) }, TestContext.Current.CancellationToken);
        GatewayException stale = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version.ConnectorId, "submit", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", stale.Code); Assert.Equal(secretCount, provider.SecretInvocations); Assert.Equal(transportCount, transport.Invocations);
        Assert.Equal(1, vendor.Requests); Assert.Equal(0, attackerVendor.Requests);

        string rotatedCanary = "m5-e2e-rotated-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        provider.Register("instrumented://rotated", rotatedCanary); vendor.ExpectedApiKey = rotatedCanary;
        ConnectorVersionResource version2 = await ImportAndValidateSampleAsync(editor, editorCsrf, TestContext.Current.CancellationToken, "2.0.0");
        object binding2 = new
        {
            environmentId, connectorVersion = version2.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = $"https://approved.vendor.example:{vendor.Port}/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "instrumented", resourceId = "api-key", resourceType = "Secret", version = "api-v1" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "instrumented", resourceId = "certificate", resourceType = "ClientCertificate", version = "cert-resource-v1", publicMetadataRevision = 1 } }
        };
        using (HttpResponseMessage response = await PutBindingAsync(editor, version2.ConnectorId, binding2, editorCsrf, null)) response.EnsureSuccessStatusCode();
        using HttpRequestMessage requestApproval2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approval-requests"); requestApproval2.Headers.Add("X-CSRF-TOKEN", editorCsrf);
        using HttpResponseMessage requested2 = await editor.SendAsync(requestApproval2, TestContext.Current.CancellationToken); requested2.EnsureSuccessStatusCode();
        JsonElement approvalRequest2 = await requested2.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        using HttpResponseMessage reviewResponse2 = await editor.GetAsync($"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approval-review", TestContext.Current.CancellationToken); reviewResponse2.EnsureSuccessStatusCode();
        JsonElement review2 = await reviewResponse2.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        using HttpRequestMessage approve2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId = approvalRequest2.GetProperty("id").GetString(), expectedDigestSha256 = review2.GetProperty("digestSha256").GetString() }) }; approve2.Headers.Add("X-CSRF-TOKEN", approverCsrf);
        using (HttpResponseMessage approved2 = await approver.SendAsync(approve2, TestContext.Current.CancellationToken)) approved2.EnsureSuccessStatusCode();
        using HttpRequestMessage publish2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}:publish") { Content = JsonContent.Create(new { expectedRowVersion = version2.RowVersion, expectedPublicationRevision = 1 }) }; publish2.Headers.Add("X-CSRF-TOKEN", approverCsrf); publish2.Headers.TryAddWithoutValidation("If-Match", $"\"{version2.RowVersion}\"");
        using (HttpResponseMessage published2 = await approver.SendAsync(publish2, TestContext.Current.CancellationToken)) published2.EnsureSuccessStatusCode();
        GatewayInvokeRequest rotatedInvocation = invocation with { CorrelationId = Guid.NewGuid() };
        _ = await runtime.InvokeAsync(new(identity, rotatedInvocation.CorrelationId), version2.ConnectorId, "submit", rotatedInvocation, TestContext.Current.CancellationToken);
        Assert.Equal(2, provider.SecretInvocations); Assert.Equal(2, transport.Invocations); Assert.Equal(2, vendor.Requests); Assert.Equal(0, attackerVendor.Requests); Assert.Equal(rotatedInvocation.CorrelationId, vendor.CorrelationId);

        _ = await store.RegisterProviderResourceAsync(rotatedResource with { Id = Guid.NewGuid(), Status = ProviderResourceStatus.Disabled, Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = DateTimeOffset.UtcNow.AddSeconds(2) }, TestContext.Current.CancellationToken);
        GatewayException disabled = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version2.ConnectorId, "submit", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", disabled.Code); Assert.Equal(2, provider.SecretInvocations); Assert.Equal(2, transport.Invocations); Assert.Equal(2, vendor.Requests); Assert.Equal(0, attackerVendor.Requests);
        IAdminDirectoryStore directory = factory.Services.GetRequiredService<IAdminDirectoryStore>();
        string auditJson = JsonSerializer.Serialize(await directory.ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken));
        Assert.DoesNotContain(canary, auditJson, StringComparison.Ordinal);
        Assert.DoesNotContain(rotatedCanary, auditJson, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, reviewJson, StringComparison.Ordinal);
    }
    [Fact]
    public async Task M5_IT_Anonymous_is_denied_and_security_headers_are_present()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/admin/api/v1/dashboard", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task M5_IT_Middleware_denial_is_fail_closed_when_persistent_audit_fails()
    {
        await using DenialAuditFailureFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/admin/api/v1/dashboard", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Empty(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents());
    }

    [Fact]
    public async Task M5_IT_Mutation_without_CSRF_is_denied()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpResponseMessage response = await client.PostAsJsonAsync("/admin/api/v1/tenants", new { code = "missing-csrf", displayName = "Missing CSRF" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("BGW-ADMIN-CSRF", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        GatewayAuditEvent denial = Assert.Single(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents(), value => value.Outcome == "denied");
        Assert.Equal("BGW-ADMIN-CSRF", denial.ReasonCode);
        Assert.Equal("admin.request.denied", denial.Action);
        Assert.Equal("method", Assert.Single(denial.Metadata.Keys));
        Assert.DoesNotContain("missing-csrf", System.Text.Json.JsonSerializer.Serialize(denial), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Viewer_cannot_mutate_but_can_read()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpResponseMessage read = await client.GetAsync("/admin/api/v1/tenants", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        using HttpRequestMessage mutation = new(HttpMethod.Post, "/admin/api/v1/tenants") { Content = JsonContent.Create(new { code = "viewer-denied", displayName = "Viewer denied" }) };
        mutation.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage denied = await client.SendAsync(mutation, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        GatewayAuditEvent audit = Assert.Single(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents(), value => value.Outcome == "denied");
        Assert.Equal("BGW-ADMIN-AUTHORIZATION", audit.ReasonCode);
        Assert.Equal(denied.Headers.GetValues("X-Correlation-ID").Single(), audit.CorrelationId.ToString("D"));
    }

    [Fact]
    public async Task M5_IT_Security_admin_creates_resources_and_activation_is_returned_once()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await CreateAndGetIdAsync(client, "/admin/api/v1/tenants", new { code = "tenant-m5", displayName = "Tenant M5" }, csrf);
        Guid applicationId = await CreateAndGetIdAsync(client, "/admin/api/v1/applications", new { code = "app-m5", displayName = "App M5", minimumBrokerVersion = "3.0.0", maximumBrokerVersion = (string?)null }, csrf);
        using (HttpRequestMessage updateTenant = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Tenant M5 updated" }) })
        {
            updateTenant.Headers.Add("X-CSRF-TOKEN", csrf);
            updateTenant.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
            using HttpResponseMessage updated = await client.SendAsync(updateTenant, TestContext.Current.CancellationToken);
            updated.EnsureSuccessStatusCode();
        }
        using (HttpRequestMessage disableApplication = new(HttpMethod.Post, $"/admin/api/v1/applications/{applicationId:D}:disable"))
        {
            disableApplication.Headers.Add("X-CSRF-TOKEN", csrf);
            disableApplication.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
            using HttpResponseMessage disabled = await client.SendAsync(disableApplication, TestContext.Current.CancellationToken);
            disabled.EnsureSuccessStatusCode();
        }
        GatewayAuditEvent[] atomicAudit = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().ToArray();
        Assert.Single(atomicAudit, value => value.Action == "tenant.update" && value.TargetId == tenantId.ToString("D"));
        Assert.Single(atomicAudit, value => value.Action == "application.disable" && value.TargetId == applicationId.ToString("D"));

        // Development catalogue is seeded only with resources explicitly created by this test.
        Guid environmentId = Guid.NewGuid();
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        await registry.AddEnvironmentAsync(new(environmentId, "local", "Local", false), TestContext.Current.CancellationToken);
        using HttpRequestMessage create = new(HttpMethod.Post, "/admin/api/v1/installations") { Content = JsonContent.Create(new { tenantId, applicationId, environmentId, installationKind = "Direct" }) };
        create.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(create, TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Contains("activationCode", body, StringComparison.Ordinal);
        using HttpRequestMessage createLegacyCompatible = new(HttpMethod.Post, "/admin/api/v1/installations") { Content = JsonContent.Create(new { tenantId, applicationId, environmentId }) };
        createLegacyCompatible.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage legacyCompatible = await client.SendAsync(createLegacyCompatible, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, legacyCompatible.StatusCode);
        using HttpResponseMessage listed = await client.GetAsync($"/admin/api/v1/installations?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
        string listBody = await listed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.DoesNotContain("activationCode", listBody, StringComparison.OrdinalIgnoreCase);
        using JsonDocument listDocument = JsonDocument.Parse(listBody);
        JsonElement list = listDocument.RootElement;
        Assert.Contains(list.GetProperty("items").EnumerateArray(), value => value.GetProperty("installationKind").GetString() == "Direct");
        Assert.Contains(list.GetProperty("items").EnumerateArray(), value => value.GetProperty("installationKind").GetString() == "Broker");
        Assert.DoesNotContain("certificateDer", listBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private", listBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(registry.SnapshotAuditEvents(), value => value.Action == "installation.create" && value.Metadata.TryGetValue("installationKind", out string? kind) && kind == "Direct");
    }

    [Fact]
    public async Task Installation_lookup_and_audit_export_are_authenticated_and_tenant_role_scoped()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient anonymous = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        Guid tenantId = Guid.NewGuid(), otherTenant = Guid.NewGuid(), applicationId = Guid.NewGuid(), environmentId = Guid.NewGuid(), installationId = Guid.NewGuid();
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await registry.AddTenantAsync(new(tenantId, "lookup-tenant", "Lookup tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await registry.AddTenantAsync(new(otherTenant, "other-lookup-tenant", "Other tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "lookup-app", "Lookup app", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "lookup-env", "Lookup environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "1.0.0", now), TestContext.Current.CancellationToken);
        Guid foreignInstallationId = Guid.NewGuid();
        await registry.AddInstallationAsync(new(foreignInstallationId, otherTenant, applicationId, environmentId, InstallationStatus.Active, "1.0.0", now), TestContext.Current.CancellationToken);
        string route = $"/admin/api/v1/installations/{installationId:D}?tenantId={tenantId:D}";
        using HttpResponseMessage unauthenticated = await anonymous.GetAsync(route, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);

        const string exportInterval = "fromUtc=2026-09-10T00%3A00%3A00Z&toUtc=2026-09-11T00%3A00%3A00Z";
        using HttpResponseMessage anonymousExport = await anonymous.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&{exportInterval}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousExport.StatusCode);

        IAdminSecurityStore security = factory.Services.GetRequiredService<IAdminSecurityStore>();
        IAdminSessionStore sessions = factory.Services.GetRequiredService<IAdminSessionStore>();
        foreach (AdminRole role in Enum.GetValues<AdminRole>())
        {
            AdminExternalIdentity identity = new("https://lookup.invalid", role.ToString(), "Lookup principal", null);
            AdminPrincipalRecord principal = await security.EnsurePrincipalAsync(identity, TestContext.Current.CancellationToken);
            _ = await security.AssignRoleAsync(principal.Id, role, tenantId, principal.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
            (string handle, _) = await sessions.CreateAsync(identity, now, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
            const string scheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
            var cookie = factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>().Get(scheme);
            var ticket = new Microsoft.AspNetCore.Authentication.AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(
                new System.Security.Claims.ClaimsIdentity([new System.Security.Claims.Claim("sid", handle)], scheme)), scheme);
            using HttpClient scoped = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
            scoped.DefaultRequestHeaders.Add("Cookie", "__Host-SecureIntegration.Admin=" + cookie.TicketDataFormat.Protect(ticket));
            using HttpResponseMessage found = await scoped.GetAsync(route, TestContext.Current.CancellationToken);
            bool allowed = role is AdminRole.Viewer or AdminRole.Operator or AdminRole.SecurityAdministrator;
            Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Forbidden, found.StatusCode);
            using HttpResponseMessage searched = await scoped.GetAsync($"/admin/api/v1/installations?tenantId={tenantId:D}&filter={installationId:D}&applicationId={applicationId:D}&environmentId={environmentId:D}&limit=1", TestContext.Current.CancellationToken);
            Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Forbidden, searched.StatusCode);
            using HttpResponseMessage foreignSearch = await scoped.GetAsync($"/admin/api/v1/installations?tenantId={otherTenant:D}&filter={foreignInstallationId:D}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, foreignSearch.StatusCode);
            using HttpResponseMessage globalSearch = await scoped.GetAsync("/admin/api/v1/tenants?filter=lookup&limit=1", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, globalSearch.StatusCode);
            if (allowed)
            {
                using JsonDocument searchBody = JsonDocument.Parse(await searched.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
                Assert.Equal(1, searchBody.RootElement.GetProperty("total").GetInt32());
                Assert.Equal(installationId, searchBody.RootElement.GetProperty("items")[0].GetProperty("id").GetGuid());
            }
            using HttpResponseMessage export = await scoped.GetAsync($"/admin/api/v1/audit:export?tenantId={tenantId:D}&{exportInterval}", TestContext.Current.CancellationToken);
            Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Forbidden, export.StatusCode);
            using HttpResponseMessage foreignExport = await scoped.GetAsync($"/admin/api/v1/audit:export?tenantId={otherTenant:D}&{exportInterval}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, foreignExport.StatusCode);
            if (!allowed) continue;
            string body = await found.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            using JsonDocument metadata = JsonDocument.Parse(body);
            Assert.Equal(installationId, metadata.RootElement.GetProperty("id").GetGuid());
            Assert.Equal(environmentId, metadata.RootElement.GetProperty("environmentId").GetGuid());
            Assert.DoesNotContain("activationCode", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("certificateDer", body, StringComparison.OrdinalIgnoreCase);
            foreach (Guid requested in new[] { installationId, Guid.NewGuid() })
            {
                using HttpResponseMessage wrongScope = await scoped.GetAsync($"/admin/api/v1/installations/{requested:D}?tenantId={otherTenant:D}", TestContext.Current.CancellationToken);
                Assert.Equal(HttpStatusCode.Forbidden, wrongScope.StatusCode);
            }
            using HttpResponseMessage absent = await scoped.GetAsync($"/admin/api/v1/installations/{Guid.NewGuid():D}?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
            using HttpResponseMessage foreign = await scoped.GetAsync($"/admin/api/v1/installations/{foreignInstallationId:D}?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
            Assert.Equal(absent.StatusCode, foreign.StatusCode);
            using HttpResponseMessage noTenant = await scoped.GetAsync($"/admin/api/v1/installations/{installationId:D}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, noTenant.StatusCode);
        }
    }

    [Fact]
    public async Task M5_IT_Tenant_and_application_require_current_IfMatch_without_lost_updates()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await CreateAndGetIdAsync(client, "/admin/api/v1/tenants", new { code = "etag-tenant", displayName = "Original tenant" }, csrf);
        Guid applicationId = await CreateAndGetIdAsync(client, "/admin/api/v1/applications", new { code = "etag-app", displayName = "Original app", minimumBrokerVersion = "3.0.0", maximumBrokerVersion = (string?)null }, csrf);

        using HttpResponseMessage tenantGet = await client.GetAsync($"/admin/api/v1/tenants/{tenantId:D}", TestContext.Current.CancellationToken);
        Assert.Equal("\"1\"", tenantGet.Headers.ETag?.Tag);
        using HttpRequestMessage missing = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Missing precondition" }) };
        missing.Headers.Add("X-CSRF-TOKEN", csrf); using HttpResponseMessage missingResponse = await client.SendAsync(missing, TestContext.Current.CancellationToken); Assert.Equal((HttpStatusCode)428, missingResponse.StatusCode);
        using HttpRequestMessage tenantA = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Admin A" }) };
        tenantA.Headers.Add("X-CSRF-TOKEN", csrf); tenantA.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage tenantAResponse = await client.SendAsync(tenantA, TestContext.Current.CancellationToken); tenantAResponse.EnsureSuccessStatusCode();
        using HttpRequestMessage tenantB = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Admin B" }) };
        tenantB.Headers.Add("X-CSRF-TOKEN", csrf); tenantB.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage tenantBResponse = await client.SendAsync(tenantB, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Conflict, tenantBResponse.StatusCode);
        JsonElement currentTenant = await tenantAResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken); Assert.Equal("Admin A", currentTenant.GetProperty("displayName").GetString()); Assert.Equal(2, currentTenant.GetProperty("rowVersion").GetInt64());

        using HttpResponseMessage applicationGet = await client.GetAsync($"/admin/api/v1/applications/{applicationId:D}", TestContext.Current.CancellationToken); Assert.Equal("\"1\"", applicationGet.Headers.ETag?.Tag);
        using HttpRequestMessage applicationA = new(HttpMethod.Put, $"/admin/api/v1/applications/{applicationId:D}") { Content = JsonContent.Create(new { displayName = "Admin A", minimumBrokerVersion = "3.1.0", maximumBrokerVersion = (string?)null }) };
        applicationA.Headers.Add("X-CSRF-TOKEN", csrf); applicationA.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage applicationAResponse = await client.SendAsync(applicationA, TestContext.Current.CancellationToken); applicationAResponse.EnsureSuccessStatusCode();
        using HttpRequestMessage applicationB = new(HttpMethod.Post, $"/admin/api/v1/applications/{applicationId:D}:disable");
        applicationB.Headers.Add("X-CSRF-TOKEN", csrf); applicationB.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage applicationBResponse = await client.SendAsync(applicationB, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Conflict, applicationBResponse.StatusCode);
        Assert.Equal(2, factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Count(value => value.Action is "tenant.update" or "application.update"));
    }

    [Fact]
    public async Task M5_IT_Logout_invalidates_cookie_session()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage logout = new(HttpMethod.Post, "/admin/auth/logout"); logout.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage signedOut = await client.SendAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, signedOut.StatusCode);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using HttpResponseMessage me = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Captured_cookie_cannot_be_replayed_after_logout()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        (string csrf, string capturedCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage logout = new(HttpMethod.Post, "/admin/auth/logout");
        logout.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage signedOut = await client.SendAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, signedOut.StatusCode);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, "/admin/auth/me");
        request.Headers.Add("Cookie", capturedCookie);
        request.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage denied = await replay.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Reauthentication_rotates_session_and_invalidates_the_previous_cookie()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        (_, string firstCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        (_, string secondCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        Assert.NotEqual(firstCookie, secondCookie);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage oldRequest = new(HttpMethod.Get, "/admin/auth/me");
        oldRequest.Headers.Add("Cookie", firstCookie);
        oldRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage oldResponse = await replay.SendAsync(oldRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, oldResponse.StatusCode);

        using HttpRequestMessage currentRequest = new(HttpMethod.Get, "/admin/auth/me");
        currentRequest.Headers.Add("Cookie", secondCookie);
        currentRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage currentResponse = await replay.SendAsync(currentRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, currentResponse.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Role_revocation_immediately_invalidates_all_target_sessions()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient viewer = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(viewer, "viewer", TestContext.Current.CancellationToken);

        using HttpClient administrator = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string adminCsrf = await LoginAsync(administrator, "security-admin", TestContext.Current.CancellationToken);
        using HttpRequestMessage assign = new(HttpMethod.Post, "/admin/api/v1/role-assignments")
        {
            Content = JsonContent.Create(new { principal = new { issuer = "https://development.invalid", subject = "viewer", displayName = "viewer" }, role = "Operator", tenantId = (Guid?)null })
        };
        assign.Headers.Add("X-CSRF-TOKEN", adminCsrf);
        using HttpResponseMessage assignedResponse = await administrator.SendAsync(assign, TestContext.Current.CancellationToken);
        assignedResponse.EnsureSuccessStatusCode();
        System.Text.Json.JsonElement assigned = await assignedResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        (_, string refreshedViewerCookie) = await LoginAndCaptureCookieAsync(viewer, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage revoke = new(HttpMethod.Delete, $"/admin/api/v1/role-assignments/{assigned.GetProperty("id").GetGuid():D}");
        revoke.Headers.Add("X-CSRF-TOKEN", adminCsrf);
        using HttpResponseMessage revoked = await administrator.SendAsync(revoke, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, "/admin/auth/me");
        request.Headers.Add("Cookie", refreshedViewerCookie);
        request.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage response = await replay.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Role_assignment_is_server_authorized_and_audited()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/role-assignments")
        {
            Content = JsonContent.Create(new { principal = new { issuer = "https://issuer.example.test", subject = "audited-viewer", displayName = "Audited viewer", email = (string?)null }, role = "Viewer", tenantId = (Guid?)null })
        };
        request.Headers.Add("X-CSRF-TOKEN", csrf);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        GatewayAuditEvent audit = Assert.Single(registry.SnapshotAuditEvents(), value => value.Action == "admin.role.assign" && value.TargetId != value.ActorId);
        Assert.Equal("success", audit.Outcome);
        Assert.DoesNotContain("issuer.example.test", System.Text.Json.JsonSerializer.Serialize(audit), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ADMIN_ROLE_exact_existing_self_assignment_HTTP_is_an_idempotent_noop()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        int auditCountBefore = registry.SnapshotAuditEvents().Count(value => value.Action == "admin.role.assign");
        using HttpRequestMessage request = RoleAssignmentRequest("security-admin", "Viewer", null, csrf);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(auditCountBefore, registry.SnapshotAuditEvents().Count(value => value.Action == "admin.role.assign"));
        using HttpResponseMessage stillAuthorized = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, stillAuthorized.StatusCode);
    }

    [Fact]
    public async Task ADMIN_ROLE_self_escalation_to_new_role_HTTP_is_denied()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpRequestMessage request = RoleAssignmentRequest("security-admin", "Operator", null, csrf);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("SecurityAdministrator", body, StringComparison.Ordinal);
        Assert.DoesNotContain("admin_role_assignment", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task M5_IT_Canonical_connector_sample_is_served_validated_and_imported_as_Draft()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);

        using HttpResponseMessage schema = await client.GetAsync("/admin/api/v1/connectors/schema", TestContext.Current.CancellationToken);
        using HttpResponseMessage sample = await client.GetAsync("/admin/api/v1/connectors/sample", TestContext.Current.CancellationToken);
        schema.EnsureSuccessStatusCode();
        sample.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument definition = await System.Text.Json.JsonDocument.ParseAsync(await sample.Content.ReadAsStreamAsync(TestContext.Current.CancellationToken), cancellationToken: TestContext.Current.CancellationToken);

        using HttpRequestMessage validate = new(HttpMethod.Post, "/admin/api/v1/connectors:validate") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone())) };
        validate.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage validationResponse = await client.SendAsync(validate, TestContext.Current.CancellationToken);
        ConnectorValidationResult result = (await validationResponse.Content.ReadFromJsonAsync<ConnectorValidationResult>(cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.True(result.Valid);
        Assert.Empty(result.Issues);

        using HttpRequestMessage import = new(HttpMethod.Post, "/admin/api/v1/connectors:import") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone(), result.ChecksumSha256)) };
        import.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage importResponse = await client.SendAsync(import, TestContext.Current.CancellationToken);
        string importJson = await importResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"state\":\"Draft\"", importJson, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Created, importResponse.StatusCode);
    }

    [Fact]
    public async Task M5_SEC_grant_creation_denies_missing_wrong_draft_retired_version_and_unknown_operation_before_mutation()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        (Guid tenantId, Guid installationId, ConnectorVersionRecord validated) = await SeedGrantContextAsync(factory, client, csrf);
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        ConnectorVersionRecord draft = await CreateGrantVersionAsync(store, validated, "2.0.0", ConnectorVersionState.Draft);
        ConnectorVersionRecord retired = await CreateGrantVersionAsync(store, validated, "3.0.0", ConnectorVersionState.Retired);
        int connectorCount = (await store.ListConnectorsAsync(TestContext.Current.CancellationToken)).Count;

        object[] invalidRequests =
        [
            new { tenantId, installationId, connectorId = validated.ConnectorSlug, operationId = "submit" },
            new { tenantId, installationId, connectorId = validated.ConnectorSlug, connectorVersion = "9.9.9", operationId = "submit" },
            new { tenantId, installationId, connectorId = "missing-connector", connectorVersion = validated.Version, operationId = "submit" },
            new { tenantId, installationId, connectorId = validated.ConnectorSlug, connectorVersion = draft.Version, operationId = "submit" },
            new { tenantId, installationId, connectorId = validated.ConnectorSlug, connectorVersion = retired.Version, operationId = "submit" },
            new { tenantId, installationId, connectorId = validated.ConnectorSlug, connectorVersion = validated.Version, operationId = "not-in-definition" }
        ];
        HttpStatusCode[] expected = [HttpStatusCode.BadRequest, HttpStatusCode.NotFound, HttpStatusCode.NotFound, HttpStatusCode.Conflict, HttpStatusCode.Conflict, HttpStatusCode.NotFound];
        for (int index = 0; index < invalidRequests.Length; index++)
        {
            using HttpResponseMessage response = await PostGrantAsync(client, csrf, invalidRequests[index]);
            Assert.Equal(expected[index], response.StatusCode);
        }

        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        Assert.Empty(registry.SnapshotDirectory().Grants);
        Assert.DoesNotContain(registry.SnapshotAuditEvents(), value => string.Equals(value.Action, "grant.create", StringComparison.Ordinal));
        Assert.Equal(connectorCount, (await store.ListConnectorsAsync(TestContext.Current.CancellationToken)).Count);
        Assert.DoesNotContain(await store.ListConnectorsAsync(TestContext.Current.CancellationToken), value => string.Equals(value.ConnectorId, "missing-connector", StringComparison.Ordinal));
    }

    [Fact]
    public async Task M5_IT_grant_creation_is_sequentially_idempotent_and_revalidates_existing_noop_authority()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        (Guid tenantId, Guid installationId, ConnectorVersionRecord version) = await SeedGrantContextAsync(factory, client, csrf);
        object request = new { tenantId, installationId, connectorId = version.ConnectorSlug, connectorVersion = version.Version, operationId = "submit" };

        using HttpResponseMessage first = await PostGrantAsync(client, csrf, request);
        using HttpResponseMessage second = await PostGrantAsync(client, csrf, request);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        JsonElement firstBody = await first.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        JsonElement secondBody = await second.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(firstBody.GetProperty("id").GetGuid(), secondBody.GetProperty("id").GetGuid());

        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        Assert.Single(registry.SnapshotDirectory().Grants);
        Assert.Single(registry.SnapshotAuditEvents(), value => string.Equals(value.Action, "grant.create", StringComparison.Ordinal));

        using HttpResponseMessage changedExpiry = await PostGrantAsync(client, csrf, new { tenantId, installationId, connectorId = version.ConnectorSlug, connectorVersion = version.Version, operationId = "submit", validUntil = DateTimeOffset.UtcNow.AddDays(1) });
        Assert.Equal(HttpStatusCode.Conflict, changedExpiry.StatusCode);
        Assert.Single(registry.SnapshotDirectory().Grants);
        Assert.Single(registry.SnapshotAuditEvents(), value => string.Equals(value.Action, "grant.create", StringComparison.Ordinal));

        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        _ = await store.RetireAsync(version.Id, version.RowVersion, "security-admin", Guid.NewGuid(), DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        using HttpResponseMessage invalidNoop = await PostGrantAsync(client, csrf, request);
        Assert.Equal(HttpStatusCode.Conflict, invalidNoop.StatusCode);
        Assert.Single(registry.SnapshotDirectory().Grants);
        Assert.Single(registry.SnapshotAuditEvents(), value => string.Equals(value.Action, "grant.create", StringComparison.Ordinal));
    }

    [Fact]
    public async Task M5_IT_Binding_update_requires_current_IfMatch_and_precondition_failures_do_not_mutate()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        await factory.Services.GetRequiredService<InMemoryGatewayRegistry>().AddEnvironmentAsync(new(environmentId, "binding-test", "Binding test", false), TestContext.Current.CancellationToken);
        ConnectorVersionResource version = await ImportAndValidateSampleAsync(client, csrf, TestContext.Current.CancellationToken);
        await RegisterCatalogResourcesAsync(factory, environmentId, version.ConnectorId);
        object body = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "synthetic", resourceId = "api-key", resourceType = "Secret" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "synthetic", resourceId = "certificate", resourceType = "ClientCertificate", publicMetadataRevision = 1 } }
        };

        using HttpResponseMessage created = await PutBindingAsync(client, version.ConnectorId, body, csrf, null);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(1, (await created.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken)).GetProperty("revision").GetInt64());

        using HttpResponseMessage missing = await PutBindingAsync(client, version.ConnectorId, body, csrf, null);
        Assert.Equal((HttpStatusCode)428, missing.StatusCode);
        using HttpResponseMessage stale = await PutBindingAsync(client, version.ConnectorId, body, csrf, "\"99\"");
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        GatewayAuditEvent[] denials = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Where(value => value.Outcome == "denied").ToArray();
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONCURRENCY-PRECONDITION");
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONCURRENCY-CONFLICT");

        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        ConnectorVersionRecord stored = (await store.GetVersionAsync(version.ConnectorId, version.Version, TestContext.Current.CancellationToken))!;
        Assert.Equal(1, (await store.ListBindingsPageAsync(stored.Id, 0, 50, environmentId, TestContext.Current.CancellationToken)).Total);

        using HttpResponseMessage updated = await PutBindingAsync(client, version.ConnectorId, body, csrf, "\"1\"");
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal(2, (await updated.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken)).GetProperty("revision").GetInt64());
    }

    [Fact]
    public async Task M5_IT_Security_denials_for_binding_policy_self_approval_and_bootstrap_are_redacted_once()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        await factory.Services.GetRequiredService<InMemoryGatewayRegistry>().AddEnvironmentAsync(new(environmentId, "denial-test", "Denial test", false), TestContext.Current.CancellationToken);
        ConnectorVersionResource version = await ImportAndValidateSampleAsync(client, csrf, TestContext.Current.CancellationToken);
        await RegisterCatalogResourcesAsync(factory, environmentId, version.ConnectorId);
        object invalidBinding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["attacker-endpoint"] = "https://controlled.example.test/" },
            secretResources = new Dictionary<string, object> { ["attacker-secret"] = new { providerId = "synthetic", resourceId = "ACTUAL_API_KEY_CANARY", resourceType = "Secret" } }
        };
        using HttpResponseMessage bindingDenied = await PutBindingAsync(client, version.ConnectorId, invalidBinding, csrf, null);
        Assert.Equal(HttpStatusCode.BadRequest, bindingDenied.StatusCode);

        object validBinding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "synthetic", resourceId = "api-key", resourceType = "Secret" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "synthetic", resourceId = "certificate", resourceType = "ClientCertificate", publicMetadataRevision = 1 } }
        };
        using HttpResponseMessage bindingCreated = await PutBindingAsync(client, version.ConnectorId, validBinding, csrf, null);
        bindingCreated.EnsureSuccessStatusCode();
        using HttpRequestMessage approvalRequest = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-requests");
        approvalRequest.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage requested = await client.SendAsync(approvalRequest, TestContext.Current.CancellationToken);
        requested.EnsureSuccessStatusCode();
        using JsonDocument requestedBody = JsonDocument.Parse(await requested.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using HttpResponseMessage reviewResponse = await client.GetAsync($"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-review", TestContext.Current.CancellationToken);
        reviewResponse.EnsureSuccessStatusCode(); string reviewJson = await reviewResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument review = JsonDocument.Parse(reviewJson);
        Assert.Equal("vendor.example.test", review.RootElement.GetProperty("artifact").GetProperty("operations")[0].GetProperty("endpoint").GetProperty("hostname").GetString());
        Assert.Equal(requestedBody.RootElement.GetProperty("bindingDigestSha256").GetString(), review.RootElement.GetProperty("digestSha256").GetString());
        Assert.Contains("api-key", reviewJson, StringComparison.Ordinal); Assert.DoesNotContain("secretValue", reviewJson, StringComparison.OrdinalIgnoreCase);
        Guid approvalRequestId = requestedBody.RootElement.GetProperty("id").GetGuid();
        using HttpRequestMessage staleApprove = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId, expectedDigestSha256 = new string('A', 64) }) };
        staleApprove.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage staleApproval = await client.SendAsync(staleApprove, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, staleApproval.StatusCode);
        using HttpRequestMessage approve = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId, expectedDigestSha256 = requestedBody.RootElement.GetProperty("bindingDigestSha256").GetString() }) };
        approve.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage selfApproval = await client.SendAsync(approve, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, selfApproval.StatusCode);

        using HttpRequestMessage bootstrap = new(HttpMethod.Post, "/admin/api/v1/bootstrap");
        bootstrap.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage bootstrapDenied = await client.SendAsync(bootstrap, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, bootstrapDenied.StatusCode);

        GatewayAuditEvent[] denials = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Where(value => value.Outcome == "denied").ToArray();
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONNECTOR-BINDING-SCOPE");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-FOUR-EYES");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-APPROVAL-STALE");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-BOOTSTRAP-DENIED");
        Assert.All(denials, value => { Assert.Equal("admin.request.denied", value.Action); Assert.Equal("method", Assert.Single(value.Metadata.Keys)); });
        Assert.DoesNotContain("canary-not-a-secret", System.Text.Json.JsonSerializer.Serialize(denials), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void M5_IT_DevelopmentAuth_cannot_start_in_Production()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
        });
        Assert.ThrowsAny<Exception>(() => factory.CreateClient());
    }

    [Fact]
    public void M5_IT_Production_cannot_disable_four_eyes()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("four-eyes", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void M5_IT_Oidc_cannot_disable_four_eyes_even_in_test_environment()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Oidc");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("OIDC requires four-eyes", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Explicit_loopback_development_can_use_development_publication_policy()
    {
        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        Assert.IsType<DevelopmentConnectorApprovalPolicy>(factory.Services.GetRequiredService<IConnectorApprovalPolicy>());
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("192.0.2.25", false)]
    [InlineData("203.0.113.10", false)]
    public void M5_UT_DevelopmentAuth_uses_actual_socket_peer_only(string address, bool expected) =>
        Assert.Equal(expected, DevelopmentAuthenticationBoundary.IsLoopbackPeer(System.Net.IPAddress.Parse(address)));

    [Theory]
    [InlineData("172.29.44.1", true)]
    [InlineData("::ffff:172.29.44.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("172.29.44.5", false)]
    [InlineData("192.0.2.25", false)]
    public void M5_UT_DevelopmentAuth_compose_peer_is_exact_and_server_owned(string address, bool expected)
    {
        DefaultHttpContext context = new();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(address);
        context.Request.Headers["X-Forwarded-For"] = "172.29.44.1";
        Assert.Equal(expected, DevelopmentAuthenticationBoundary.IsAllowedPeer(context.Connection.RemoteIpAddress, System.Net.IPAddress.Parse("172.29.44.1")));
    }

    [Theory]
    [InlineData("Production", "172.29.44.1", false, false)]
    [InlineData("Development", "172.29.44.1", false, false)]
    [InlineData("Testing", "172.29.44.1", false, false)]
    [InlineData("M5Testing", "172.29.44.1", true, false)]
    [InlineData("M5Testing", "172.29.44.0/28", false, false)]
    [InlineData("M5Testing", "0.0.0.0", false, false)]
    [InlineData("M5Testing", "203.0.113.10", false, false)]
    [InlineData("M5Testing", "172.29.44.1", false, true)]
    public void M5_UT_DevelopmentAuth_compose_peer_is_test_only_without_forwarding(string environment, string peer, bool forwarded, bool allowed)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        GatewayAdminOptions options = new() { Mode = "DevelopmentAuth", DevelopmentPeerAddress = peer, TrustedProxies = forwarded ? ["172.29.44.1"] : [] };
        if (allowed) builder.AddGatewayAdminAuthentication(options);
        else Assert.Throws<InvalidOperationException>(() => builder.AddGatewayAdminAuthentication(options));
    }

    [Fact]
    public void M5_UT_Remote_peer_cannot_forge_loopback_with_Host_or_forwarded_headers()
    {
        DefaultHttpContext context = new();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.0.2.25");
        context.Request.Host = new HostString("localhost");
        context.Request.Headers["X-Forwarded-For"] = "127.0.0.1";
        context.Request.Headers["X-Forwarded-Host"] = "localhost";
        Assert.False(DevelopmentAuthenticationBoundary.IsLoopbackPeer(context.Connection.RemoteIpAddress));
    }

    [Fact]
    public void M5_CT_DevelopmentAuth_compose_listener_is_explicitly_loopback_only()
    {
        string compose = File.ReadAllText(Path.Combine(RepositoryRoot(), "deploy", "m5", "docker-compose.m5.yml"));
        Assert.Contains("127.0.0.1:${M5_GATEWAY_PORT:-18443}:8443", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("0.0.0.0", compose, StringComparison.Ordinal);
    }

    [Fact]
    public void M5_CT_Full_stack_runner_precreates_nested_read_only_mount_points()
    {
        string runner = File.ReadAllText(Path.Combine(RepositoryRoot(), "tools", "m5", "Invoke-M5FullStack.ps1"));
        int nodeMount = runner.IndexOf("New-Item -ItemType Directory -Path $nodeMountPoint", StringComparison.Ordinal);
        int resultsMount = runner.IndexOf("New-Item -ItemType Directory -Path $resultsMountPoint", StringComparison.Ordinal);
        int dockerRun = runner.IndexOf("& docker run", StringComparison.Ordinal);

        Assert.True(nodeMount >= 0 && nodeMount < dockerRun);
        Assert.True(resultsMount >= 0 && resultsMount < dockerRun);
        Assert.Contains("$createdNodeMountPoint", runner, StringComparison.Ordinal);
        Assert.Contains("$createdResultsMountPoint", runner, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $nodeMountPoint -Force", runner, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $resultsMountPoint -Force", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("--read-only=false", runner, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Development_login_route_is_unavailable_when_mode_is_disabled()
    {
        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
        });
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await GetCsrfAsync(client, TestContext.Current.CancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = "viewer" }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static async Task<(Guid TenantId, Guid InstallationId, ConnectorVersionRecord Version)> SeedGrantContextAsync(AdminDevelopmentFactory factory, HttpClient client, string csrf)
    {
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
        IAdminGatewayRegistry registry = factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        await registry.AddTenantAsync(new(tenantId, "grant-" + tenantId.ToString("N"), "Grant tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "grant-" + applicationId.ToString("N"), "Grant application", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "grant-" + environmentId.ToString("N")[..20], "Grant environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "1.0.0", now), TestContext.Current.CancellationToken);
        ConnectorVersionResource resource = await ImportAndValidateSampleAsync(client, csrf, TestContext.Current.CancellationToken);
        ConnectorVersionRecord version = await factory.Services.GetRequiredService<IConnectorConfigurationStore>().GetVersionAsync(resource.ConnectorId, resource.Version, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Validated grant test Connector version was not persisted.");
        return (tenantId, installationId, version);
    }

    private static async Task<ConnectorVersionRecord> CreateGrantVersionAsync(IConnectorConfigurationStore store, ConnectorVersionRecord source, string version, ConnectorVersionState targetState)
    {
        using JsonDocument definition = JsonDocument.Parse(source.CanonicalJson.Replace($"\"version\":\"{source.Version}\"", $"\"version\":\"{version}\"", StringComparison.Ordinal));
        ValidatedConnectorDefinition canonical = new ConnectorDefinitionValidator().ValidateRequired(definition.RootElement);
        ConnectorVersionRecord draft = await store.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, source.ConnectorSlug, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), "grant-test", DateTimeOffset.UtcNow, 0), TestContext.Current.CancellationToken);
        if (targetState == ConnectorVersionState.Draft) return draft;
        ConnectorVersionRecord validated = await store.MarkValidatedAsync(draft.Id, draft.RowVersion, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        return targetState == ConnectorVersionState.Retired
            ? await store.RetireAsync(validated.Id, validated.RowVersion, "grant-test", Guid.NewGuid(), DateTimeOffset.UtcNow, TestContext.Current.CancellationToken)
            : validated;
    }

    private static async Task<HttpResponseMessage> PostGrantAsync(HttpClient client, string csrf, object body)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/grants") { Content = JsonContent.Create(body) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> LoginAsync(HttpClient client, string user, CancellationToken cancellationToken)
    {
        string csrf = await GetCsrfAsync(client, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await GetCsrfAsync(client, cancellationToken);
    }

    private static HttpRequestMessage RoleAssignmentRequest(string subject, string role, Guid? tenantId, string csrf)
    {
        HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/role-assignments")
        {
            Content = JsonContent.Create(new
            {
                principal = new { issuer = "https://development.invalid", subject, displayName = subject, email = (string?)null },
                role,
                tenantId
            })
        };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        return request;
    }

    private static async Task<(string Csrf, string Cookie)> LoginAndCaptureCookieAsync(HttpClient client, string user, CancellationToken cancellationToken)
    {
        string csrf = await GetCsrfAsync(client, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        string setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith("__Host-SecureIntegration.Admin=", StringComparison.Ordinal));
        return (await GetCsrfAsync(client, cancellationToken), setCookie[..setCookie.IndexOf(';')]);
    }

    private static async Task<ConnectorVersionResource> ImportAndValidateSampleAsync(HttpClient client, string csrf, CancellationToken cancellationToken, string? version = null)
    {
        using HttpResponseMessage sample = await client.GetAsync("/admin/api/v1/connectors/sample", cancellationToken);
        sample.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument source = await System.Text.Json.JsonDocument.ParseAsync(await sample.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        using System.Text.Json.JsonDocument definition = version is null ? System.Text.Json.JsonDocument.Parse(source.RootElement.GetRawText()) : System.Text.Json.JsonDocument.Parse(source.RootElement.GetRawText().Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal));
        using HttpRequestMessage validate = new(HttpMethod.Post, "/admin/api/v1/connectors:validate") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone())) };
        validate.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage validationResponse = await client.SendAsync(validate, cancellationToken);
        ConnectorValidationResult validation = (await validationResponse.Content.ReadFromJsonAsync<ConnectorValidationResult>(cancellationToken: cancellationToken))!;
        using HttpRequestMessage import = new(HttpMethod.Post, "/admin/api/v1/connectors:import") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone(), validation.ChecksumSha256)) };
        import.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage importResponse = await client.SendAsync(import, cancellationToken);
        ConnectorVersionResource draft = (await importResponse.Content.ReadFromJsonAsync<ConnectorVersionResource>(WireJson, cancellationToken))!;
        using HttpRequestMessage markValidated = new(HttpMethod.Post, $"/admin/api/v1/connectors/{draft.ConnectorId}/versions/{draft.Version}:validate");
        markValidated.Headers.Add("X-CSRF-TOKEN", csrf);
        markValidated.Headers.TryAddWithoutValidation("If-Match", $"\"{draft.RowVersion}\"");
        using HttpResponseMessage validated = await client.SendAsync(markValidated, cancellationToken);
        validated.EnsureSuccessStatusCode();
        return (await validated.Content.ReadFromJsonAsync<ConnectorVersionResource>(WireJson, cancellationToken))!;
    }

    private static Task<HttpResponseMessage> PutBindingAsync(HttpClient client, string connectorId, object body, string csrf, string? etag)
    {
        HttpRequestMessage request = new(HttpMethod.Put, $"/admin/api/v1/connectors/{connectorId}/bindings") { Content = JsonContent.Create(body) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        if (etag is not null) request.Headers.TryAddWithoutValidation("If-Match", etag);
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task RegisterCatalogResourcesAsync(AdminDevelopmentFactory factory, Guid environmentId, string connectorId)
    {
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "api-key", ProviderResourceType.Secret, "Vendor API key", environmentId, connectorId, "submit", "synthetic://api-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now), TestContext.Current.CancellationToken);
        CertificatePublicMetadata metadata = new(new string('A', 64), "CN=Synthetic client", "CN=Synthetic issuer", now.AddDays(-1), now.AddDays(30), "RSA", 2048, "1");
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "certificate", ProviderResourceType.ClientCertificate, "Vendor certificate", environmentId, connectorId, "submit", "synthetic://certificate", ProviderResourceStatus.Active, null, 0, 1, metadata, string.Empty, now), TestContext.Current.CancellationToken);
    }

    private static async Task<string> GetCsrfAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", cancellationToken);
        response.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument json = await System.Text.Json.JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        return json.RootElement.GetProperty("token").GetString()!;
    }

    private static async Task<Guid> CreateAndGetIdAsync(HttpClient client, string path, object body, string csrf)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, path) { Content = JsonContent.Create(body) }; request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken); response.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument json = await System.Text.Json.JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(TestContext.Current.CancellationToken), cancellationToken: TestContext.Current.CancellationToken);
        return json.RootElement.GetProperty("id").GetGuid();
    }

    private sealed class InstrumentedProvider(string canary, byte[] pfx) : ISecretValueProvider, IClientCertificateProvider
    {
        private readonly Dictionary<string, string> secrets = new(StringComparer.Ordinal) { ["instrumented://api-key"] = canary };
        public int SecretInvocations { get; private set; }
        public int CertificateInvocations { get; private set; }

        public void Register(string logicalReference, string value) => secrets[logicalReference] = value;

        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SecretInvocations++;
            return Task.FromResult(secrets.TryGetValue(logicalReference, out string? value) ? value : throw new InvalidOperationException("Unknown synthetic secret reference."));
        }

        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal("instrumented://certificate", logicalReference);
            CertificateInvocations++;
            return Task.FromResult(X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable));
        }
    }

    private sealed class CountingRestrictedTransport(IRestrictedTransport inner) : IRestrictedTransport
    {
        public int Invocations { get; private set; }

        public async Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Invocations++;
            return await inner.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
        }
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class ExactLoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) =>
            string.Equals(candidateHost, host, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class CertificateSet : IDisposable
    {
        private readonly RSA rootKey;
        private readonly RSA serverKey;
        private readonly RSA clientKey;

        private CertificateSet(RSA rootKey, RSA serverKey, RSA clientKey, X509Certificate2 root, X509Certificate2 server, X509Certificate2 client)
        {
            this.rootKey = rootKey; this.serverKey = serverKey; this.clientKey = clientKey;
            RootCertificate = root; ServerCertificate = server; ClientCertificate = client;
        }

        public X509Certificate2 RootCertificate { get; }
        public X509Certificate2 ServerCertificate { get; }
        public X509Certificate2 ClientCertificate { get; }
        public string ClientPrivateKeyPem => clientKey.ExportPkcs8PrivateKeyPem();

        public static CertificateSet Create(string serverHost, DateTimeOffset clientExpiry)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            RSA rootKey = RSA.Create(2048); RSA serverKey = RSA.Create(2048); RSA clientKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=M5 Synthetic Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(10));

            CertificateRequest serverRequest = new($"CN={serverHost}", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new(); san.AddDnsName(serverHost); serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 issuedServer = serverRequest.Create(root, now.AddMinutes(-2), now.AddDays(2), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = issuedServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

            CertificateRequest clientRequest = new("CN=M5 near-expiry client", clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
            using X509Certificate2 issuedClient = clientRequest.Create(root, now.AddMinutes(-2), clientExpiry, RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 clientWithKey = issuedClient.CopyWithPrivateKey(clientKey);
            X509Certificate2 client = X509CertificateLoader.LoadPkcs12(clientWithKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(rootKey, serverKey, clientKey, root, server, client);
        }

        public void Dispose()
        {
            ClientCertificate.Dispose(); ServerCertificate.Dispose(); RootCertificate.Dispose();
            clientKey.Dispose(); serverKey.Dispose(); rootKey.Dispose();
        }
    }

    private sealed class RealVendorMock : IAsyncDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource cancellation = new();
        private readonly X509Certificate2 serverCertificate;
        private string expectedApiKey;
        private readonly string expectedFingerprint;
        private Task? serverTask;

        private RealVendorMock(TcpListener listener, X509Certificate2 serverCertificate, string expectedApiKey, string expectedFingerprint)
        {
            this.listener = listener; this.serverCertificate = serverCertificate; this.expectedApiKey = expectedApiKey; this.expectedFingerprint = expectedFingerprint;
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        public int Port { get; }
        public int Requests { get; private set; }
        public bool ApiKeyMatched { get; private set; }
        public bool ClientCertificateMatched { get; private set; }
        public Guid? CorrelationId { get; private set; }
        public string ExpectedApiKey { get => expectedApiKey; set => expectedApiKey = value; }

        public static Task<RealVendorMock> StartAsync(CertificateSet certificates, string expectedApiKey, string expectedFingerprint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TcpListener listener = new(IPAddress.Loopback, 0); listener.Start();
            RealVendorMock mock = new(listener, certificates.ServerCertificate, expectedApiKey, expectedFingerprint);
            mock.serverTask = mock.RunAsync();
            return Task.FromResult(mock);
        }

        private async Task RunAsync()
        {
            try
            {
                while (!cancellation.IsCancellationRequested)
                {
                    using TcpClient client = await listener.AcceptTcpClientAsync(cancellation.Token);
                    await HandleAsync(client);
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (SocketException) when (cancellation.IsCancellationRequested) { }
        }

        private async Task HandleAsync(TcpClient client)
        {
                using SslStream tls = new(client.GetStream(), false, (_, certificate, _, _) =>
                {
                    ClientCertificateMatched = certificate is not null && string.Equals(Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())), expectedFingerprint, StringComparison.Ordinal);
                    return ClientCertificateMatched;
                });
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellation.Token);
                byte[] terminator = "\r\n\r\n"u8.ToArray();
                using MemoryStream headerBuffer = new();
                int matched = 0;
                while (headerBuffer.Length < 16384)
                {
                    int value = tls.ReadByte(); if (value < 0) throw new IOException("Unexpected end of HTTPS request.");
                    headerBuffer.WriteByte((byte)value);
                    matched = value == terminator[matched] ? matched + 1 : value == terminator[0] ? 1 : 0;
                    if (matched == terminator.Length) break;
                }
                string[] lines = Encoding.ASCII.GetString(headerBuffer.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                Dictionary<string, string> headers = lines.Skip(1).Select(line => line.Split(':', 2)).Where(parts => parts.Length == 2)
                    .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
                if (headers.TryGetValue("Content-Length", out string? lengthText) && int.TryParse(lengthText, out int length) && length > 0)
                {
                    byte[] body = new byte[length]; await tls.ReadExactlyAsync(body, cancellation.Token);
                }
                Requests++;
                ApiKeyMatched = headers.TryGetValue("X-Vendor-Api-Key", out string? key) && string.Equals(key, expectedApiKey, StringComparison.Ordinal);
                CorrelationId = headers.TryGetValue("X-Correlation-ID", out string? correlationText) && Guid.TryParse(correlationText, out Guid correlation) ? correlation : null;
                string response = ApiKeyMatched && ClientCertificateMatched
                    ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 43\r\n\r\n{\"accepted\":true,\"credential\":\"[REDACTED]\"}"
                    : "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                await tls.WriteAsync(Encoding.ASCII.GetBytes(response), cancellation.Token);
                await tls.FlushAsync(cancellation.Token);
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.Cancel(); listener.Stop();
            if (serverTask is not null) { try { await serverTask; } catch (SocketException) when (cancellation.IsCancellationRequested) { } }
            cancellation.Dispose();
        }
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    public sealed class PostgresRuntimeRoleLease : IAsyncDisposable
    {
        private readonly string migrationConnectionString;
        private readonly string roleName;

        private PostgresRuntimeRoleLease(string connectionString, string migrationConnectionString, string roleName)
        {
            ConnectionString = connectionString;
            this.migrationConnectionString = migrationConnectionString;
            this.roleName = roleName;
        }

        public string ConnectionString { get; }

        public static async Task<PostgresRuntimeRoleLease> CreateAsync(string adminConnectionString, string migrationConnectionString, CancellationToken cancellationToken)
        {
            string roleName = "m5_e2e_runtime_" + Guid.NewGuid().ToString("N");
            string rolePassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            await using NpgsqlConnection connection = new(migrationConnectionString);
            await connection.OpenAsync(cancellationToken);
            await using NpgsqlCommand command = new($"CREATE ROLE {roleName} LOGIN PASSWORD '{rolePassword}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; GRANT gateway_runtime TO {roleName};", connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            NpgsqlConnectionStringBuilder runtime = new(adminConnectionString) { Username = roleName, Password = rolePassword };
            return new(runtime.ConnectionString, migrationConnectionString, roleName);
        }

        public async ValueTask DisposeAsync()
        {
            await using NpgsqlConnection connection = new(migrationConnectionString);
            await connection.OpenAsync();
            await using NpgsqlCommand command = new($"DROP ROLE IF EXISTS {roleName};", connection);
            await command.ExecuteNonQueryAsync();
        }
    }
}

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class AdminApiPostgreSqlSecurityTests
{
    [Fact]
    public Task M5_E2E_Admin_searches_10000_PostgreSQL_tenants_with_bounded_results() =>
        AdminApiSecurityTests.RunPostgreSqlTenantSearchAsync();

    [Fact]
    public Task M5_E2E_Admin_approval_publish_runtime_provider_transport_prevents_credential_exfiltration() =>
        AdminApiSecurityTests.RunPostgreSqlApprovalPublishAntiExfiltrationAsync();

    [Fact]
    public async Task M5_IT_DAT_PostgreSQL18_concurrent_identical_grant_posts_converge_to_one_row_and_audit()
    {
        await using PostgreSqlRoleRaceContext context = await PostgreSqlRoleRaceContext.CreateAsync();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
        await context.Registry.AddTenantAsync(new(tenantId, "grant-" + tenantId.ToString("N"), "Grant tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await context.Registry.AddApplicationAsync(new(applicationId, "grant-" + applicationId.ToString("N"), "Grant application", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await context.Registry.AddEnvironmentAsync(new(environmentId, "grant-" + environmentId.ToString("N")[..20], "Grant environment", false), TestContext.Current.CancellationToken);
        await context.Registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "1.0.0", now), TestContext.Current.CancellationToken);
        ConnectorVersionRecord version = await context.CreateValidatedGrantVersionAsync("grant-" + Guid.NewGuid().ToString("N"));
        object body = new { tenantId, installationId, connectorId = version.ConnectorSlug, connectorVersion = version.Version, operationId = "submit" };

        (HttpResponseMessage first, HttpResponseMessage second) = await context.SendGrantPairAsync(body);
        using (first)
        using (second)
        {
            Assert.All(new[] { first, second }, response => Assert.True(response.IsSuccessStatusCode));
            Assert.Equal([HttpStatusCode.OK, HttpStatusCode.Created], new[] { first.StatusCode, second.StatusCode }.Order().ToArray());
            JsonElement firstBody = await first.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            JsonElement secondBody = await second.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(firstBody.GetProperty("id").GetGuid(), secondBody.GetProperty("id").GetGuid());
            Guid grantId = firstBody.GetProperty("id").GetGuid();
            Assert.Equal(1L, await context.ScalarTenantAsync(tenantId, "SELECT count(*) FROM gateway.installation_connector_grant g JOIN gateway.connector_definition c ON c.id=g.connector_id WHERE g.installation_id=$1 AND c.slug=$2 AND g.operation_id=$3", installationId, version.ConnectorSlug, "submit"));
            Assert.Equal(1L, await context.ScalarTenantAsync(tenantId, "SELECT count(*) FROM gateway.audit_event WHERE tenant_id=$1 AND action='grant.create' AND target_id=$2", tenantId, grantId.ToString("D")));
        }
    }

    [Fact]
    public async Task ADMIN_ROLE_concurrent_identical_first_assignment_converges_to_one_row_and_two_successes()
    {
        await using PostgreSqlRoleRaceContext context = await PostgreSqlRoleRaceContext.CreateAsync();
        for (int iteration = 0; iteration < 4; iteration++)
        {
            AdminExternalIdentity target = NewTarget("first-" + iteration);
            (string _, AdminSessionRecord targetSession) = await context.Sessions.CreateAsync(target, DateTimeOffset.UtcNow, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
            using HttpResponseMessage first = await context.SendPairAsync(context.Editor, context.EditorCsrf, context.Approver, context.ApproverCsrf, target, AdminRole.Operator);
            using HttpResponseMessage second = context.SecondResponse!;
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(HttpStatusCode.OK, second.StatusCode);
            JsonElement firstBody = await first.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            JsonElement secondBody = await second.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(firstBody.GetProperty("id").GetGuid(), secondBody.GetProperty("id").GetGuid());
            Assert.Equal(1L, await context.ScalarAsync("SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role='operator' AND tenant_id IS NULL", targetSession.Principal.Id));
            Assert.Equal(1L, await context.ScalarAsync("SELECT count(*) FROM gateway.audit_event WHERE action='admin.role.assign' AND target_id=$1", targetSession.Principal.Id.ToString("D")));
            Assert.Equal(1L, await context.ScalarAsync("SELECT count(*) FROM gateway.admin_session WHERE id=$1 AND revoked_at IS NOT NULL", targetSession.Id));
        }
    }

    [Fact]
    public async Task ADMIN_ROLE_concurrent_identical_tenant_scoped_first_assignment_converges_bounded()
    {
        await using PostgreSqlRoleRaceContext context = await PostgreSqlRoleRaceContext.CreateAsync();
        for (int iteration = 0; iteration < 4; iteration++)
        {
            Guid tenantId = Guid.NewGuid();
            await context.Registry.AddTenantAsync(
                new(
                    tenantId,
                    "role-race-tenant-" + tenantId.ToString("N"),
                    "Role race tenant",
                    TenantStatus.Active,
                    DateTimeOffset.UtcNow),
                TestContext.Current.CancellationToken);
            AdminExternalIdentity target = NewTarget("tenant-first-" + iteration);
            (_, AdminSessionRecord targetSession) = await context.Sessions.CreateAsync(
                target,
                DateTimeOffset.UtcNow,
                TimeSpan.FromHours(1),
                TimeSpan.FromMinutes(20),
                TestContext.Current.CancellationToken);

            using HttpResponseMessage first = await context.SendPairAsync(
                context.Editor,
                context.EditorCsrf,
                context.Approver,
                context.ApproverCsrf,
                target,
                AdminRole.Operator,
                tenantId);
            using HttpResponseMessage second = context.SecondResponse!;

            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(HttpStatusCode.OK, second.StatusCode);
            string firstBody = await first.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            string secondBody = await second.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            AssertNoDatabaseInternals(firstBody);
            AssertNoDatabaseInternals(secondBody);
            using JsonDocument firstDocument = JsonDocument.Parse(firstBody);
            using JsonDocument secondDocument = JsonDocument.Parse(secondBody);
            Guid assignmentId = firstDocument.RootElement.GetProperty("id").GetGuid();
            Assert.Equal(assignmentId, secondDocument.RootElement.GetProperty("id").GetGuid());
            Assert.Equal(
                1L,
                await context.ScalarAsync(
                    "SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role='operator' AND tenant_id=$2",
                    targetSession.Principal.Id,
                    tenantId));
            Assert.Equal(
                1L,
                await context.ScalarAsync(
                    "SELECT count(*) FROM gateway.admin_role_assignment WHERE id=$1 AND principal_id=$2 AND tenant_id=$3",
                    assignmentId,
                    targetSession.Principal.Id,
                    tenantId));
            Assert.Equal(
                1L,
                await context.ScalarTenantAsync(
                    tenantId,
                    "SELECT count(*) FROM gateway.audit_event WHERE action='admin.role.assign' AND target_id=$1",
                    targetSession.Principal.Id.ToString("D")));
            Assert.Equal(
                1L,
                await context.ScalarAsync(
                    "SELECT count(*) FROM gateway.admin_session WHERE id=$1 AND revoked_at IS NOT NULL",
                    targetSession.Id));
        }
    }

    [Fact]
    public async Task ADMIN_ROLE_concurrent_existing_noops_do_not_revoke_or_extend_sessions()
    {
        await using PostgreSqlRoleRaceContext context = await PostgreSqlRoleRaceContext.CreateAsync();
        AdminExternalIdentity target = NewTarget("no-op");
        (_, AdminSessionRecord original) = await context.Sessions.CreateAsync(target, DateTimeOffset.UtcNow, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        _ = await context.Security.AssignRoleAsync(original.Principal.Id, AdminRole.Viewer, null, context.EditorPrincipal.Id, Guid.NewGuid(), DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        (_, AdminSessionRecord active) = await context.Sessions.CreateAsync(target, DateTimeOffset.UtcNow, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        long auditBefore = await context.ScalarAsync("SELECT count(*) FROM gateway.audit_event WHERE action='admin.role.assign' AND target_id=$1", active.Principal.Id.ToString("D"));
        DateTimeOffset absoluteExpiryBefore = await context.TimestampAsync("SELECT absolute_expires_at FROM gateway.admin_session WHERE id=$1", active.Id);
        DateTimeOffset idleExpiryBefore = await context.TimestampAsync("SELECT idle_expires_at FROM gateway.admin_session WHERE id=$1", active.Id);

        using HttpResponseMessage first = await context.SendPairAsync(context.Editor, context.EditorCsrf, context.Approver, context.ApproverCsrf, target, AdminRole.Viewer);
        using HttpResponseMessage second = context.SecondResponse!;

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(auditBefore, await context.ScalarAsync("SELECT count(*) FROM gateway.audit_event WHERE action='admin.role.assign' AND target_id=$1", active.Principal.Id.ToString("D")));
        Assert.Equal(0L, await context.ScalarAsync("SELECT count(*) FROM gateway.admin_session WHERE id=$1 AND revoked_at IS NOT NULL", active.Id));
        Assert.Equal(absoluteExpiryBefore, await context.TimestampAsync("SELECT absolute_expires_at FROM gateway.admin_session WHERE id=$1", active.Id));
        Assert.Equal(idleExpiryBefore, await context.TimestampAsync("SELECT idle_expires_at FROM gateway.admin_session WHERE id=$1", active.Id));
    }

    [Fact]
    public async Task ADMIN_ROLE_concurrent_different_assignments_remain_distinct()
    {
        await using PostgreSqlRoleRaceContext context = await PostgreSqlRoleRaceContext.CreateAsync();
        AdminExternalIdentity target = NewTarget("distinct");
        (_, AdminSessionRecord targetSession) = await context.Sessions.CreateAsync(target, DateTimeOffset.UtcNow, TimeSpan.FromHours(1), TimeSpan.FromMinutes(20), TestContext.Current.CancellationToken);
        Task<HttpResponseMessage> viewer = PostgreSqlRoleRaceContext.SendAsync(context.Editor, context.EditorCsrf, target, AdminRole.Viewer, null);
        Task<HttpResponseMessage> operatorRole = PostgreSqlRoleRaceContext.SendAsync(context.Approver, context.ApproverCsrf, target, AdminRole.Operator, null);
        HttpResponseMessage[] responses = await Task.WhenAll(viewer, operatorRole);
        using HttpResponseMessage first = responses[0]; using HttpResponseMessage second = responses[1];

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        Assert.Equal(2L, await context.ScalarAsync("SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role IN ('viewer','operator') AND tenant_id IS NULL", targetSession.Principal.Id));

        Guid firstTenant = Guid.NewGuid();
        Guid secondTenant = Guid.NewGuid();
        await context.Registry.AddTenantAsync(new(firstTenant, "role-scope-" + firstTenant.ToString("N"), "Role scope A", TenantStatus.Active, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        await context.Registry.AddTenantAsync(new(secondTenant, "role-scope-" + secondTenant.ToString("N"), "Role scope B", TenantStatus.Active, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        Task<HttpResponseMessage> firstScope = PostgreSqlRoleRaceContext.SendAsync(context.Editor, context.EditorCsrf, target, AdminRole.Viewer, firstTenant);
        Task<HttpResponseMessage> secondScope = PostgreSqlRoleRaceContext.SendAsync(context.Approver, context.ApproverCsrf, target, AdminRole.Viewer, secondTenant);
        HttpResponseMessage[] scopedResponses = await Task.WhenAll(firstScope, secondScope);
        using HttpResponseMessage firstScoped = scopedResponses[0]; using HttpResponseMessage secondScoped = scopedResponses[1];

        Assert.All(scopedResponses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
        Assert.Equal(2L, await context.ScalarAsync("SELECT count(*) FROM gateway.admin_role_assignment WHERE principal_id=$1 AND role='viewer' AND tenant_id IS NOT NULL", targetSession.Principal.Id));
    }

    private static AdminExternalIdentity NewTarget(string kind)
    {
        string subject = "role-race-" + kind + "-" + Guid.NewGuid().ToString("N");
        return new("https://role-race.example.test", subject, "Role race", null);
    }

    private static void AssertNoDatabaseInternals(string body)
    {
        Assert.DoesNotContain("23505", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SQLSTATE", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Npgsql", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PostgreSQL", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ux_admin_role_assignment_scope", body, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class PostgreSqlRoleRaceContext : IAsyncDisposable
    {
        private readonly string adminConnectionString;
        private readonly AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole;
        private readonly AntiExfiltrationFactory factory;

        private PostgreSqlRoleRaceContext(string adminConnectionString, AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole, AntiExfiltrationFactory factory, AdminPostgresDataSource dataSource, PostgresAdminSecurityStore security, PostgresAdminSessionStore sessions, AdminPrincipalRecord editorPrincipal, HttpClient editor, string editorCsrf, HttpClient approver, string approverCsrf)
        {
            this.adminConnectionString = adminConnectionString; this.runtimeRole = runtimeRole; this.factory = factory; DataSource = dataSource; Registry = new(dataSource.Value); Security = security; Sessions = sessions; EditorPrincipal = editorPrincipal; Editor = editor; EditorCsrf = editorCsrf; Approver = approver; ApproverCsrf = approverCsrf;
        }

        internal AdminPostgresDataSource DataSource { get; }
        internal PostgresGatewayRegistry Registry { get; }
        internal PostgresAdminSecurityStore Security { get; }
        internal PostgresAdminSessionStore Sessions { get; }
        internal AdminPrincipalRecord EditorPrincipal { get; }
        internal HttpClient Editor { get; }
        internal string EditorCsrf { get; }
        internal HttpClient Approver { get; }
        internal string ApproverCsrf { get; }
        internal HttpResponseMessage? SecondResponse { get; private set; }

        internal static async Task<PostgreSqlRoleRaceContext> CreateAsync()
        {
            string? adminConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
            string? migrationConnectionString = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
            if (string.IsNullOrWhiteSpace(adminConnectionString) || string.IsNullOrWhiteSpace(migrationConnectionString))
                Assert.Skip("The PostgreSQL role-convergence scenario requires the dedicated PostgreSQL 18 gate.");
            AdminPostgresDataSource dataSource = new(adminConnectionString);
            PostgresAdminSecurityStore security = new(dataSource);
            AdminPrincipalRecord editorPrincipal = await EnsureSecurityAdministratorAsync(security, "editor");
            _ = await EnsureSecurityAdministratorAsync(security, "approver");
            AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole = await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnectionString, migrationConnectionString, TestContext.Current.CancellationToken);
            AntiExfiltrationFactory factory = new(runtimeRole.ConnectionString, adminConnectionString);
            HttpClient editor = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
            HttpClient approver = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
            string editorCsrf = await LoginAsync(editor, "editor");
            string approverCsrf = await LoginAsync(approver, "approver");
            return new(adminConnectionString, runtimeRole, factory, dataSource, security, new(dataSource, security), editorPrincipal, editor, editorCsrf, approver, approverCsrf);
        }

        internal async Task<HttpResponseMessage> SendPairAsync(HttpClient firstClient, string firstCsrf, HttpClient secondClient, string secondCsrf, AdminExternalIdentity target, AdminRole role, Guid? tenantId = null)
        {
            Task<HttpResponseMessage> first = SendAsync(firstClient, firstCsrf, target, role, tenantId);
            Task<HttpResponseMessage> second = SendAsync(secondClient, secondCsrf, target, role, tenantId);
            HttpResponseMessage[] responses = await Task.WhenAll(first, second).ConfigureAwait(false);
            SecondResponse = responses[1];
            return responses[0];
        }

        internal async Task<(HttpResponseMessage First, HttpResponseMessage Second)> SendGrantPairAsync(object body)
        {
            Task<HttpResponseMessage> first = SendGrantAsync(Editor, EditorCsrf, body);
            Task<HttpResponseMessage> second = SendGrantAsync(Approver, ApproverCsrf, body);
            HttpResponseMessage[] responses = await Task.WhenAll(first, second).ConfigureAwait(false);
            return (responses[0], responses[1]);
        }

        internal async Task<ConnectorVersionRecord> CreateValidatedGrantVersionAsync(string connectorId)
        {
            DirectoryInfo? directory = new(AppContext.BaseDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx"))) directory = directory.Parent;
            string root = directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
            using JsonDocument source = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "docs", "connectors", "examples", "sample-secure-service.connector.json"), TestContext.Current.CancellationToken));
            using JsonDocument definition = JsonDocument.Parse(source.RootElement.GetRawText().Replace("sample-secure-service", connectorId, StringComparison.Ordinal));
            ValidatedConnectorDefinition canonical = new ConnectorDefinitionValidator().ValidateRequired(definition.RootElement);
            PostgresConnectorConfigurationStore store = new(DataSource.Value);
            ConnectorVersionRecord draft = await store.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, canonical.Version, canonical.SchemaVersion, ConnectorVersionState.Draft, canonical.CanonicalJson, Convert.FromHexString(canonical.ChecksumSha256), "grant-test", DateTimeOffset.UtcNow, 0), TestContext.Current.CancellationToken);
            return await store.MarkValidatedAsync(draft.Id, draft.RowVersion, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        }

        internal static async Task<HttpResponseMessage> SendAsync(HttpClient client, string csrf, AdminExternalIdentity target, AdminRole role, Guid? tenantId)
        {
            using HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/role-assignments") { Content = JsonContent.Create(new { principal = target, role, tenantId }) };
            request.Headers.Add("X-CSRF-TOKEN", csrf);
            return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(false);
        }

        private static async Task<HttpResponseMessage> SendGrantAsync(HttpClient client, string csrf, object body)
        {
            using HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/grants") { Content = JsonContent.Create(body) };
            request.Headers.Add("X-CSRF-TOKEN", csrf);
            return await client.SendAsync(request, TestContext.Current.CancellationToken).ConfigureAwait(false);
        }

        internal async Task<long> ScalarAsync(string sql, params object[] values)
        {
            await using NpgsqlConnection connection = new(adminConnectionString); await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using NpgsqlCommand command = new(sql, connection);
            foreach (object value in values) command.Parameters.AddWithValue(value);
            return Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        }

        internal async Task<long> ScalarTenantAsync(Guid tenantId, string sql, params object[] values)
        {
            await using NpgsqlConnection connection = new(adminConnectionString);
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await using (NpgsqlCommand context = new("SELECT set_config('app.tenant_id',$1,true)", connection, transaction))
            {
                context.Parameters.AddWithValue(tenantId.ToString("D"));
                _ = await context.ExecuteScalarAsync(TestContext.Current.CancellationToken);
            }
            await using NpgsqlCommand command = new(sql, connection, transaction);
            foreach (object value in values) command.Parameters.AddWithValue(value);
            long result = Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken), System.Globalization.CultureInfo.InvariantCulture);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
            return result;
        }

        internal async Task<DateTimeOffset> TimestampAsync(string sql, object value)
        {
            await using NpgsqlConnection connection = new(adminConnectionString); await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using NpgsqlCommand command = new(sql, connection); command.Parameters.AddWithValue(value);
            object timestamp = (await command.ExecuteScalarAsync(TestContext.Current.CancellationToken))!;
            return timestamp switch
            {
                DateTimeOffset offset => offset,
                DateTime dateTime => new DateTimeOffset(DateTime.SpecifyKind(dateTime, DateTimeKind.Utc)),
                _ => throw new InvalidOperationException("POSTGRES_ROLE_RACE_TIMESTAMP_INVALID")
            };
        }

        public async ValueTask DisposeAsync()
        {
            SecondResponse?.Dispose(); Editor.Dispose(); Approver.Dispose(); await factory.DisposeAsync(); await runtimeRole.DisposeAsync(); await DataSource.DisposeAsync();
        }

        private static async Task<AdminPrincipalRecord> EnsureSecurityAdministratorAsync(PostgresAdminSecurityStore security, string subject)
        {
            AdminPrincipalRecord principal = await security.EnsurePrincipalAsync(new("https://development.invalid", subject, subject, subject + "@example.test"), TestContext.Current.CancellationToken);
            _ = await security.AssignRoleAsync(principal.Id, AdminRole.SecurityAdministrator, null, principal.Id, Guid.NewGuid(), DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            return principal;
        }

        private static async Task<string> LoginAsync(HttpClient client, string user)
        {
            string csrf = await GetCsrfAsync(client);
            using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
            request.Headers.Add("X-CSRF-TOKEN", csrf);
            using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken); response.EnsureSuccessStatusCode();
            return await GetCsrfAsync(client);
        }

        private static async Task<string> GetCsrfAsync(HttpClient client)
        {
            using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", TestContext.Current.CancellationToken); response.EnsureSuccessStatusCode();
            JsonElement body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            return body.GetProperty("token").GetString()!;
        }
    }
}

public class AdminDevelopmentFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
    }
}

/// <summary>PostgreSQL-backed host used only for the definitive cross-layer anti-exfiltration test.</summary>
public sealed class AntiExfiltrationFactory(string runtimeConnectionString, string adminConnectionString) : AdminDevelopmentFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("ConnectionStrings:GatewayDatabase", runtimeConnectionString);
        builder.UseSetting("ConnectionStrings:GatewayAdminDatabase", adminConnectionString);
        builder.ConfigureServices(services =>
        {
            services.Configure<RateLimiterOptions>(options => options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                RateLimitPartition.GetFixedWindowLimiter("anti-exfiltration", _ => new FixedWindowRateLimiterOptions { PermitLimit = 1000, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true })));
        });
    }
}

public sealed class DenialAuditFailureFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IAdminTransactionFaultInjector>();
            services.AddSingleton<IAdminTransactionFaultInjector>(new DenialAuditFaultInjector());
        });
    }

    private sealed class DenialAuditFaultInjector : IAdminTransactionFaultInjector
    {
        public void Check(string boundary)
        {
            if (boundary == "audit.append.before-state") throw new InvalidOperationException("Synthetic audit persistence failure.");
        }
    }
}
