using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Development-only administrative catalogue over the in-memory registry.</summary>
public sealed class InMemoryAdminDirectoryStore(InMemoryGatewayRegistry registry) : IAdminDirectoryStore
{
    /// <inheritdoc />
    public Task<AdminPage<TenantRecord>> ListTenantsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null)
    {
        string search = AdminDirectoryFilter.Normalize(filter);
        return Page(registry.SnapshotDirectory().Tenants.Where(value => (value.Id.ToString("D").Equals(search, StringComparison.OrdinalIgnoreCase) || AdminDirectoryFilter.Matches(value.Code, value.DisplayName, search))).OrderBy(value => value.Code).ThenBy(value => value.Id), offset, limit, cancellationToken);
    }

    /// <inheritdoc />
    public Task<TenantRecord?> GetTenantAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(registry.SnapshotDirectory().Tenants.SingleOrDefault(value => value.Id == tenantId));
    }

    /// <inheritdoc />
    public Task<AdminPage<ApplicationRecord>> ListApplicationsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null)
    {
        string search = AdminDirectoryFilter.Normalize(filter);
        return Page(registry.SnapshotDirectory().Applications.Where(value => (value.Id.ToString("D").Equals(search, StringComparison.OrdinalIgnoreCase) || AdminDirectoryFilter.Matches(value.Code, value.DisplayName, search))).OrderBy(value => value.Code).ThenBy(value => value.Id), offset, limit, cancellationToken);
    }

    /// <inheritdoc />
    public Task<ApplicationRecord?> GetApplicationAsync(Guid applicationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(registry.SnapshotDirectory().Applications.SingleOrDefault(value => value.Id == applicationId));
    }

    /// <inheritdoc />
    public Task<AdminPage<GatewayEnvironmentRecord>> ListEnvironmentsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null)
    {
        string search = AdminDirectoryFilter.Normalize(filter);
        return Page(registry.SnapshotDirectory().Environments.Where(value => (value.Id.ToString("D").Equals(search, StringComparison.OrdinalIgnoreCase) || AdminDirectoryFilter.Matches(value.Code, value.DisplayName, search))).OrderBy(value => value.Code).ThenBy(value => value.Id), offset, limit, cancellationToken);
    }

    /// <inheritdoc />
    public Task<AdminPage<InstallationRecord>> ListInstallationsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken, string? filter = null, Guid? applicationId = null, Guid? environmentId = null)
    {
        string search = AdminDirectoryFilter.Normalize(filter);
        return Page(registry.SnapshotDirectory().Installations.Where(value => value.TenantId == tenantId &&
            (applicationId is null || value.ApplicationId == applicationId) && (environmentId is null || value.EnvironmentId == environmentId) &&
            value.Id.ToString("D").Contains(search, StringComparison.OrdinalIgnoreCase)).OrderByDescending(value => value.CreatedAt).ThenBy(value => value.Id), offset, limit, cancellationToken);
    }

    /// <inheritdoc />
    public Task<InstallationRecord?> GetInstallationAsync(Guid tenantId, Guid installationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(registry.SnapshotDirectory().Installations.SingleOrDefault(value => value.TenantId == tenantId && value.Id == installationId));
    }

    /// <inheritdoc />
    public Task<AdminPage<InstallationGrantRecord>> ListGrantsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Grants.Where(value => value.TenantId == tenantId).OrderBy(value => value.ConnectorId).ThenBy(value => value.OperationId), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<AdminPage<GatewayAuditEvent>> ListAuditAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken) =>
        Page(registry.SnapshotDirectory().Audit.Where(value => value.TenantId == tenantId).OrderByDescending(value => value.OccurredAt), offset, limit, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<GatewayAuditEvent>> ExportAuditAsync(Guid tenantId, DateTimeOffset fromUtc, DateTimeOffset toUtc, DateTimeOffset? beforeOccurredAtUtc, Guid? beforeId, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateExport(fromUtc, toUtc, beforeOccurredAtUtc, beforeId, limit);
        IEnumerable<GatewayAuditEvent> query = registry.SnapshotDirectory().Audit
            .Where(value => value.TenantId == tenantId && value.OccurredAt >= fromUtc && value.OccurredAt < toUtc)
            .OrderByDescending(value => value.OccurredAt)
            .ThenByDescending(value => value.Id);
        if (beforeOccurredAtUtc is not null && beforeId is not null)
            query = query.Where(value => value.OccurredAt < beforeOccurredAtUtc || (value.OccurredAt == beforeOccurredAtUtc && value.Id.CompareTo(beforeId.Value) < 0));
        return Task.FromResult<IReadOnlyList<GatewayAuditEvent>>(query.Take(limit).ToArray());
    }

    private static Task<AdminPage<T>> Page<T>(IEnumerable<T> source, int offset, int limit, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (offset < 0 || limit is < 1 or > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400);
        T[] values = source.ToArray();
        return Task.FromResult(new AdminPage<T>(values.Skip(offset).Take(limit).ToArray(), offset, limit, values.Length));
    }

    private static void ValidateExport(DateTimeOffset fromUtc, DateTimeOffset toUtc, DateTimeOffset? beforeOccurredAtUtc, Guid? beforeId, int limit)
    {
        if (fromUtc.Offset != TimeSpan.Zero || toUtc.Offset != TimeSpan.Zero || fromUtc >= toUtc || limit is < 1 or > 1001 ||
            (beforeOccurredAtUtc is null) != (beforeId is null) || (beforeOccurredAtUtc is not null && beforeOccurredAtUtc.Value.Offset != TimeSpan.Zero))
            throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT", 400);
    }
}
