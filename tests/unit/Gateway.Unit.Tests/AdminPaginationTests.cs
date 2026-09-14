using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class AdminPaginationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task M5_UT_Tenant_search_reaches_10000th_record_with_bounded_pages_and_literal_matching()
    {
        InMemoryGatewayRegistry registry = new();
        for (int index = 0; index < 10000; index++)
            await registry.AddTenantAsync(new(Guid.NewGuid(), $"tenant-{index:D5}", index >= 9998 ? "Shared name" : $"Tenant {index:D5}", TenantStatus.Active, Now), TestContext.Current.CancellationToken);
        InMemoryAdminDirectoryStore directory = new(registry);
        AdminPage<TenantRecord> last = await directory.ListTenantsAsync(0, 20, TestContext.Current.CancellationToken, " TENANT-09999 ");
        Assert.Equal(1, last.Total);
        Assert.Equal("tenant-09999", Assert.Single(last.Items).Code);
        AdminPage<TenantRecord> firstDuplicate = await directory.ListTenantsAsync(0, 1, TestContext.Current.CancellationToken, "shared NAME");
        AdminPage<TenantRecord> secondDuplicate = await directory.ListTenantsAsync(1, 1, TestContext.Current.CancellationToken, "shared NAME");
        Assert.Equal(2, firstDuplicate.Total);
        Assert.NotEqual(Assert.Single(firstDuplicate.Items).Id, Assert.Single(secondDuplicate.Items).Id);
        Assert.Empty((await directory.ListTenantsAsync(0, 20, TestContext.Current.CancellationToken, "%")).Items);
        await Assert.ThrowsAsync<GatewayException>(() => directory.ListTenantsAsync(0, 101, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<GatewayException>(() => directory.ListTenantsAsync(0, 20, TestContext.Current.CancellationToken, new string('x', 101)));
    }

    [Fact]
    public async Task M5_UT_Directory_pages_reach_records_beyond_the_first_hundred_with_stable_totals()
    {
        InMemoryGatewayRegistry registry = new();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        await registry.AddApplicationAsync(new(applicationId, "paged-app", "Paged app", ApplicationStatus.Active, "1.0.0", null, Now), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "paged-env", "Paged environment", false), TestContext.Current.CancellationToken);
        Guid firstTenant = Guid.Empty;
        for (int index = 0; index < 101; index++)
        {
            Guid tenantId = Guid.NewGuid();
            if (index == 0) firstTenant = tenantId;
            await registry.AddTenantAsync(new(tenantId, $"tenant-{index:D3}", $"Tenant {index:D3}", TenantStatus.Active, Now.AddSeconds(index)), TestContext.Current.CancellationToken);
        }
        for (int index = 0; index < 101; index++)
        {
            Guid installationId = Guid.NewGuid();
            await registry.AddInstallationAsync(new(installationId, firstTenant, applicationId, environmentId, InstallationStatus.Pending, null, Now.AddSeconds(index)), TestContext.Current.CancellationToken);
            await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, firstTenant, "connector", $"operation-{index:D3}", true, Now), TestContext.Current.CancellationToken);
            await registry.AppendAuditAsync(new(Guid.NewGuid(), Now.AddSeconds(index), firstTenant, "administrator", "actor", "page.test", "installation", installationId.ToString("D"), Guid.NewGuid(), "success", "BGW-PAGE-TEST", new Dictionary<string, string>()), TestContext.Current.CancellationToken);
        }
        InMemoryAdminDirectoryStore directory = new(registry);

        AssertPage(await directory.ListTenantsAsync(50, 1, TestContext.Current.CancellationToken), 50);
        AssertPage(await directory.ListTenantsAsync(100, 1, TestContext.Current.CancellationToken), 100);
        AssertEmptyPage(await directory.ListTenantsAsync(101, 1, TestContext.Current.CancellationToken));
        AssertPage(await directory.ListInstallationsAsync(firstTenant, 100, 1, TestContext.Current.CancellationToken), 100);
        AssertPage(await directory.ListGrantsAsync(firstTenant, 100, 1, TestContext.Current.CancellationToken), 100);
        AssertPage(await directory.ListAuditAsync(firstTenant, 100, 1, TestContext.Current.CancellationToken), 100);
    }

    [Fact]
    public async Task M5_UT_Connector_version_binding_approval_and_role_pages_reach_record_101()
    {
        IConnectorConfigurationStore connectors = new InMemoryConnectorConfigurationStore();
        ConnectorVersionRecord? firstVersion = null;
        for (int index = 0; index < 101; index++)
        {
            ConnectorVersionRecord draft = await connectors.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, "paged-connector", $"1.0.{index}", "1.0", ConnectorVersionState.Draft, "{\"displayName\":\"Paged\"}", SHA256.HashData(BitConverter.GetBytes(index)), "editor", Now.AddSeconds(index), 0), TestContext.Current.CancellationToken);
            firstVersion ??= draft;
        }
        AdminPage<ConnectorVersionRecord> versions = await connectors.ListVersionsPageAsync("paged-connector", 100, 1, null, TestContext.Current.CancellationToken);
        AssertPage(versions, 100);

        ConnectorVersionRecord validated = await connectors.MarkValidatedAsync(firstVersion!.Id, firstVersion.RowVersion, Now, TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        for (int index = 0; index < 101; index++)
        {
            long? expected = index == 0 ? null : index;
            _ = await connectors.PutBindingsAsync(new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId,
                new Dictionary<string, Uri> { ["endpoint"] = new("https://vendor.example.test/") },
                new Dictionary<string, ProviderResourceBinding> { ["secret"] = new("synthetic", "Synthetic", "synthetic", "secret", ProviderResourceType.Secret, "Secret", environmentId, "paged-connector", "*", null, 1, null, null, new string('A', 64)) },
                new Dictionary<string, ProviderResourceBinding>(), 0, Convert.ToHexString(SHA256.HashData(BitConverter.GetBytes(index))), ConnectorBindingState.Draft, Now.AddSeconds(index), "editor"), expected, Guid.NewGuid(), TestContext.Current.CancellationToken);
        }
        AssertPage(await connectors.ListBindingsPageAsync(validated.Id, 100, 1, environmentId, TestContext.Current.CancellationToken), 100);

        InMemoryAdminSecurityStore security = new();
        AdminPrincipalRecord principal = await security.EnsurePrincipalAsync(new("https://issuer.example.test", "paged", "Paged", null), TestContext.Current.CancellationToken);
        for (int index = 0; index < 101; index++)
        {
            await security.AssignRoleAsync(principal.Id, AdminRole.Viewer, Guid.NewGuid(), principal.Id, Guid.NewGuid(), Now.AddSeconds(index), TestContext.Current.CancellationToken);
            await security.RequestApprovalAsync(validated, SHA256.HashData(BitConverter.GetBytes(index)), principal.Id, Guid.NewGuid(), Now.AddSeconds(index), TestContext.Current.CancellationToken);
        }
        AssertPage(await security.ListAssignmentsAsync(100, 1, principal.Id, null, TestContext.Current.CancellationToken), 100);
        AssertPage(await security.ListApprovalsPageAsync(validated.Id, 100, 1, TestContext.Current.CancellationToken), 100);
    }

    private static void AssertPage<T>(AdminPage<T> page, int offset)
    {
        Assert.Equal(101, page.Total);
        Assert.Equal(offset, page.Offset);
        Assert.Equal(1, page.Limit);
        Assert.Single(page.Items);
    }

    private static void AssertEmptyPage<T>(AdminPage<T> page)
    {
        Assert.Equal(101, page.Total);
        Assert.Equal(101, page.Offset);
        Assert.Empty(page.Items);
    }
}
