using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Provider-neutral administrative roles.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<AdminRole>))]
public enum AdminRole
{
    /// <summary>Read-only metadata and health access.</summary>
    Viewer,
    /// <summary>Draft, validation and binding administration.</summary>
    ConnectorEditor,
    /// <summary>Distinct approval, publication and rollback authority.</summary>
    ConnectorApprover,
    /// <summary>Installation lifecycle and controlled test authority.</summary>
    Operator,
    /// <summary>Principal, role, bootstrap and security policy authority.</summary>
    SecurityAdministrator
}

/// <summary>External identity key. Email is deliberately not part of the key.</summary>
public sealed record AdminExternalIdentity(string Issuer, string Subject, string DisplayName, string? Email);

/// <summary>Persisted administrative principal.</summary>
public sealed record AdminPrincipalRecord(Guid Id, string Issuer, string Subject, string DisplayName, string? Email, bool Active, DateTimeOffset CreatedAt);

/// <summary>Role assignment optionally restricted to one tenant.</summary>
public sealed record AdminRoleAssignmentRecord(Guid Id, Guid PrincipalId, AdminRole Role, Guid? TenantId, Guid GrantedBy, DateTimeOffset GrantedAt);

/// <summary>Role assignment request identifying the target by immutable external identity.</summary>
public sealed record AdminRoleAssignmentRequest(AdminExternalIdentity Principal, AdminRole Role, Guid? TenantId);

/// <summary>Opaque, server-side administrative session resolved from a hashed browser handle.</summary>
public sealed record AdminSessionRecord(
    Guid Id,
    AdminPrincipalRecord Principal,
    DateTimeOffset CreatedAt,
    DateTimeOffset AbsoluteExpiresAt,
    DateTimeOffset IdleExpiresAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset? RevokedAt);

/// <summary>Creates, validates and revokes administrative sessions. Implementations never persist the clear handle.</summary>
public interface IAdminSessionStore
{
    /// <summary>Creates a fresh random session and returns its one-time clear handle.</summary>
    Task<(string Handle, AdminSessionRecord Session)> CreateAsync(AdminExternalIdentity identity, DateTimeOffset now, TimeSpan absoluteLifetime, TimeSpan idleLifetime, CancellationToken cancellationToken);
    /// <summary>Validates and touches a session without extending it past its absolute expiry.</summary>
    Task<AdminSessionRecord?> ValidateAsync(string handle, DateTimeOffset now, TimeSpan idleLifetime, CancellationToken cancellationToken);
    /// <summary>Revokes exactly one session.</summary>
    Task RevokeAsync(string handle, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Revokes every session for a principal after a sensitive privilege mutation.</summary>
    Task RevokePrincipalAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>Bounded administrative result page.</summary>
public sealed record AdminPage<T>(IReadOnlyList<T> Items, int Offset, int Limit, int Total);

/// <summary>Bounded keyset audit export page inside one fixed UTC interval.</summary>
public sealed record AdminAuditExportPage<T>(IReadOnlyList<T> Items, int Limit, DateTimeOffset FromUtc, DateTimeOffset ToUtc, string? Continuation, bool Partial);

/// <summary>Provider-neutral, read-only administrative catalogue. Secret values are absent by design.</summary>
public interface IAdminDirectoryStore
{
    /// <summary>Lists tenants in a bounded page.</summary>
    Task<AdminPage<TenantRecord>> ListTenantsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null);
    /// <summary>Gets one Tenant including its concurrency token.</summary>
    Task<TenantRecord?> GetTenantAsync(Guid tenantId, CancellationToken cancellationToken);
    /// <summary>Lists applications in a bounded page.</summary>
    Task<AdminPage<ApplicationRecord>> ListApplicationsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null);
    /// <summary>Gets one Application including its concurrency token.</summary>
    Task<ApplicationRecord?> GetApplicationAsync(Guid applicationId, CancellationToken cancellationToken);
    /// <summary>Lists deployment environments in a bounded page.</summary>
    Task<AdminPage<GatewayEnvironmentRecord>> ListEnvironmentsAsync(int offset, int limit, CancellationToken cancellationToken, string? filter = null);
    /// <summary>Lists installations inside one authorized tenant.</summary>
    Task<AdminPage<InstallationRecord>> ListInstallationsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken, string? filter = null, Guid? applicationId = null, Guid? environmentId = null);
    /// <summary>Gets one installation inside one authorized tenant.</summary>
    Task<InstallationRecord?> GetInstallationAsync(Guid tenantId, Guid installationId, CancellationToken cancellationToken);
    /// <summary>Lists operation grants inside one authorized tenant.</summary>
    Task<AdminPage<InstallationGrantRecord>> ListGrantsAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Lists metadata-only audit events inside one authorized tenant.</summary>
    Task<AdminPage<GatewayAuditEvent>> ListAuditAsync(Guid tenantId, int offset, int limit, CancellationToken cancellationToken);
    /// <summary>Exports metadata-only audit events inside one authorized tenant using a descending keyset cursor.</summary>
    Task<IReadOnlyList<GatewayAuditEvent>> ExportAuditAsync(Guid tenantId, DateTimeOffset fromUtc, DateTimeOffset toUtc, DateTimeOffset? beforeOccurredAtUtc, Guid? beforeId, int limit, CancellationToken cancellationToken);
}

/// <summary>Resolved principal and immutable assignments for one request.</summary>
public sealed record AdminAccessContext(AdminPrincipalRecord Principal, IReadOnlyList<AdminRoleAssignmentRecord> Assignments)
{
    /// <summary>Stable metadata-only actor identifier.</summary>
    public string ActorId => Principal.Id.ToString("D");
}

/// <summary>Approval lifecycle independent from Connector version state.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ConnectorApprovalStatus>))]
public enum ConnectorApprovalStatus
{
    /// <summary>Awaiting a distinct approver.</summary>
    Requested,
    /// <summary>Approved for the exact checksum.</summary>
    Approved,
    /// <summary>Explicitly rejected by a distinct approver.</summary>
    Rejected,
    /// <summary>No longer usable after mutation or replacement.</summary>
    Invalidated
}

/// <summary>Checksum-specific four-eyes approval record.</summary>
public sealed record ConnectorApprovalRecord(
    Guid Id,
    Guid ConnectorVersionId,
    string ChecksumSha256,
    string BindingDigestSha256,
    Guid RequestedBy,
    Guid? ApprovedBy,
    Guid? RejectedBy,
    ConnectorApprovalStatus Status,
    DateTimeOffset RequestedAt,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? RejectedAt,
    string? DecisionComment,
    DateTimeOffset? InvalidatedAt);

/// <summary>Redacted approval decision input.</summary>
public sealed record ConnectorApprovalDecisionRequest(string? Comment);
/// <summary>Approval acceptance bound to one exact request and the digest displayed to the approver.</summary>
public sealed record ConnectorApprovalAcceptanceRequest(Guid ApprovalRequestId, string ExpectedDigestSha256, string? Comment = null);

/// <summary>Minimal persistence contract for identities, roles and four-eyes records.</summary>
public interface IAdminSecurityStore
{
    /// <summary>Ensures an authenticated external identity has a non-privileged local principal.</summary>
    Task<AdminPrincipalRecord> EnsurePrincipalAsync(AdminExternalIdentity identity, CancellationToken cancellationToken);
    /// <summary>Gets active role assignments for one principal.</summary>
    Task<IReadOnlyList<AdminRoleAssignmentRecord>> GetAssignmentsAsync(Guid principalId, CancellationToken cancellationToken);
    /// <summary>Lists role assignments in a stable bounded page.</summary>
    Task<AdminPage<AdminRoleAssignmentRecord>> ListAssignmentsAsync(int offset, int limit, Guid? principalId, Guid? tenantId, CancellationToken cancellationToken);
    /// <summary>Atomically claims the one-time Security Administrator bootstrap.</summary>
    Task<bool> TryBootstrapSecurityAdministratorAsync(Guid principalId, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Assigns a role through an audited Security Administrator action; an existing exact assignment is an idempotent no-op and does not revoke sessions.</summary>
    Task<AdminRoleAssignmentRecord> AssignRoleAsync(Guid principalId, AdminRole role, Guid? tenantId, Guid grantedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Revokes one exact role assignment and its active sessions in the same transaction.</summary>
    Task<bool> RevokeRoleAsync(Guid assignmentId, Guid revokedBy, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Creates or replaces a request for the exact version checksum.</summary>
    Task<ConnectorApprovalRecord> RequestApprovalAsync(ConnectorVersionRecord version, byte[] bindingDigestSha256, Guid requester, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Approves the current request when approver and editor identities are distinct.</summary>
    Task<ConnectorApprovalRecord> ApproveAsync(Guid approvalRequestId, Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid approver, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Rejects the current exact-checksum request as a distinct approver.</summary>
    Task<ConnectorApprovalRecord> RejectAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string createdBy, Guid rejector, string? comment, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Checks for a current approval by a distinct principal.</summary>
    Task<bool> HasValidApprovalAsync(Guid connectorVersionId, byte[] checksumSha256, byte[] bindingDigestSha256, string actor, CancellationToken cancellationToken);
    /// <summary>Invalidates current approvals after an approval-relevant mutation.</summary>
    Task InvalidateApprovalsAsync(Guid connectorVersionId, DateTimeOffset now, CancellationToken cancellationToken);
    /// <summary>Lists redacted approval metadata for a Connector version.</summary>
    Task<IReadOnlyList<ConnectorApprovalRecord>> ListApprovalsAsync(Guid connectorVersionId, CancellationToken cancellationToken);
    /// <summary>Lists approval history in a stable bounded page.</summary>
    Task<AdminPage<ConnectorApprovalRecord>> ListApprovalsPageAsync(Guid connectorVersionId, int offset, int limit, CancellationToken cancellationToken);
}

/// <summary>Policy hook applied inside the Connector service, not only at the HTTP endpoint.</summary>
public interface IConnectorApprovalPolicy
{
    /// <summary>Publishes through the policy-specific, fail-closed persistence path.</summary>
    Task<ConnectorVersionRecord> PublishAsync(IConnectorConfigurationStore connectorStore, ConnectorVersionRecord version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>Default production four-eyes policy.</summary>
public sealed class FourEyesConnectorApprovalPolicy(IAdminSecurityStore store) : IConnectorApprovalPolicy
{
    /// <inheritdoc />
    public async Task<ConnectorVersionRecord> PublishAsync(IConnectorConfigurationStore connectorStore, ConnectorVersionRecord version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        byte[] bindingDigestSha256 = await connectorStore.GetBindingBundleDigestAsync(version.Id, cancellationToken).ConfigureAwait(false);
        if (!await store.HasValidApprovalAsync(version.Id, version.ChecksumSha256, bindingDigestSha256, actor, cancellationToken).ConfigureAwait(false))
            throw new GatewayException("BGW-ADMIN-APPROVAL-REQUIRED", 409);
        return await connectorStore.PublishApprovedAsync(version.Id, bindingDigestSha256, expectedRowVersion, expectedPublicationRevision, actor, correlationId, now, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Explicit non-production compatibility policy. Registration is guarded by the host environment.</summary>
public sealed class DevelopmentConnectorApprovalPolicy : IConnectorApprovalPolicy
{
    /// <inheritdoc />
    public Task<ConnectorVersionRecord> PublishAsync(IConnectorConfigurationStore connectorStore, ConnectorVersionRecord version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken) =>
        connectorStore.PublishAsync(version.Id, expectedRowVersion, expectedPublicationRevision, actor, now, cancellationToken);
}

/// <summary>Resolves claims and enforces provider-neutral RBAC with optional tenant scope.</summary>
public sealed class AdminAccessService(IAdminSecurityStore store, IAdminSessionStore sessions, IGatewayClock clock)
{
    /// <summary>Resolves the authenticated identity using issuer and subject only.</summary>
    public async Task<AdminAccessContext> ResolveAsync(ClaimsPrincipal claimsPrincipal, CancellationToken cancellationToken)
    {
        if (claimsPrincipal.Identity?.IsAuthenticated != true) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
        string? sessionHandle = claimsPrincipal.FindFirst("sid")?.Value;
        if (string.IsNullOrWhiteSpace(sessionHandle)) throw new GatewayException("BGW-ADMIN-SESSION", 401);
        AdminSessionRecord session = await sessions.ValidateAsync(sessionHandle, clock.UtcNow, TimeSpan.FromMinutes(20), cancellationToken).ConfigureAwait(false)
            ?? throw new GatewayException("BGW-ADMIN-SESSION", 401);
        AdminPrincipalRecord principal = session.Principal;
        if (!principal.Active) throw new GatewayException("BGW-ADMIN-PRINCIPAL-DISABLED", 403);
        return new(principal, await store.GetAssignmentsAsync(principal.Id, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Requires one of the supplied roles, respecting tenant scope.</summary>
    public static void Require(AdminAccessContext context, Guid? tenantId, params AdminRole[] roles)
    {
        bool allowed = roles.Any(role => HasRole(context, tenantId, role));
        if (!allowed) throw new GatewayException("BGW-ADMIN-AUTHORIZATION", 403);
    }

    /// <summary>
    /// Authorizes role administration while allowing only an exact, already-persisted
    /// self-assignment as an idempotent no-op. A principal cannot add a role or widen
    /// its own tenant scope.
    /// </summary>
    public static bool RequireRoleAssignment(AdminAccessContext context, AdminExternalIdentity target, AdminRole role, Guid? tenantId)
    {
        Require(context, tenantId, AdminRole.SecurityAdministrator);
        bool targetsSelf = string.Equals(context.Principal.Issuer, target.Issuer, StringComparison.Ordinal)
            && string.Equals(context.Principal.Subject, target.Subject, StringComparison.Ordinal);
        if (!targetsSelf) return false;

        bool exactExistingAssignment = context.Assignments.Any(assignment =>
            assignment.PrincipalId == context.Principal.Id
            && assignment.Role == role
            && assignment.TenantId == tenantId);
        if (!exactExistingAssignment) throw new GatewayException("BGW-ADMIN-AUTHORIZATION", 403);
        return true;
    }

    /// <summary>Checks one exact role while preserving global or tenant-scoped assignment semantics.</summary>
    public static bool HasRole(AdminAccessContext context, Guid? tenantId, AdminRole role) =>
        context.Assignments.Any(assignment => assignment.Role == role &&
            (assignment.TenantId is null || assignment.TenantId == tenantId));
}

/// <summary>Four-eyes request and approval application service.</summary>
public sealed class ConnectorApprovalService(IAdminSecurityStore store, IConnectorConfigurationStore connectors, IGatewayClock clock)
{
    /// <summary>Returns the exact semantic artefact that approval and publication digest.</summary>
    public async Task<ApprovalReviewResult> ReviewAsync(string connectorId, string version, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        await connectors.ValidateBindingResourcesAsync(current.Id, cancellationToken).ConfigureAwait(false);
        ConnectorBindingSet[] currentBindings = Latest((await connectors.ListBindingsPageAsync(current.Id, 0, 100, null, cancellationToken).ConfigureAwait(false)).Items);
        ApprovalReviewArtifact? previous = null;
        ConnectorVersionRecord? published = (await connectors.ListVersionsAsync(connectorId, cancellationToken).ConfigureAwait(false)).FirstOrDefault(value => value.State == ConnectorVersionState.Published && value.Id != current.Id);
        if (published is not null)
        {
            ConnectorBindingSet[] publishedBindings = Latest((await connectors.ListBindingsPageAsync(published.Id, 0, 100, null, cancellationToken).ConfigureAwait(false)).Items);
            if (publishedBindings.Length > 0) previous = ConnectorApprovalArtifacts.Create(published, publishedBindings).Artifact;
        }
        return ConnectorApprovalArtifacts.Create(current, currentBindings, previous);
    }

    /// <summary>Requests approval for the current Validated checksum.</summary>
    public async Task<ConnectorApprovalRecord> RequestAsync(string connectorId, string version, AdminAccessContext actor, Guid correlationId, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        if (current.State != ConnectorVersionState.Validated) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        await connectors.ValidateBindingResourcesAsync(current.Id, cancellationToken).ConfigureAwait(false);
        byte[] bindingDigest = await connectors.GetBindingBundleDigestAsync(current.Id, cancellationToken).ConfigureAwait(false);
        return await store.RequestApprovalAsync(current, bindingDigest, actor.Principal.Id, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Approves only as a distinct ConnectorApprover or SecurityAdministrator.</summary>
    public async Task<ConnectorApprovalRecord> ApproveAsync(string connectorId, string version, ConnectorApprovalAcceptanceRequest request, AdminAccessContext actor, Guid correlationId, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        try { if (Convert.FromHexString(request.ExpectedDigestSha256).Length != 32) throw new FormatException(); }
        catch (FormatException) { throw new GatewayException("BGW-ADMIN-APPROVAL-DIGEST", 400); }
        string? comment = string.IsNullOrWhiteSpace(request.Comment) ? null : request.Comment.Trim();
        if (comment?.Length > 500) throw new GatewayException("BGW-ADMIN-APPROVAL-COMMENT", 400);
        return await connectors.ApproveCanonicalAsync(store, request.ApprovalRequestId, current.Id, request.ExpectedDigestSha256, current.CreatedBy, actor.Principal.Id, comment, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Rejects only as a distinct ConnectorApprover or SecurityAdministrator.</summary>
    public async Task<ConnectorApprovalRecord> RejectAsync(string connectorId, string version, string? comment, AdminAccessContext actor, Guid correlationId, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        string? redactedComment = string.IsNullOrWhiteSpace(comment) ? null : comment.Trim();
        if (redactedComment?.Length > 500) throw new GatewayException("BGW-ADMIN-APPROVAL-COMMENT", 400);
        byte[] bindingDigest = await connectors.GetBindingBundleDigestAsync(current.Id, cancellationToken).ConfigureAwait(false);
        return await store.RejectAsync(current.Id, current.ChecksumSha256, bindingDigest, current.CreatedBy, actor.Principal.Id, redactedComment, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Lists approval metadata.</summary>
    public Task<IReadOnlyList<ConnectorApprovalRecord>> ListAsync(string connectorId, string version, AdminAccessContext actor, CancellationToken cancellationToken)
    {
        AdminAccessService.Require(actor, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
        return ListCoreAsync(connectorId, version, cancellationToken);
    }

    private async Task<IReadOnlyList<ConnectorApprovalRecord>> ListCoreAsync(string connectorId, string version, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        return await store.ListApprovalsAsync(current.Id, cancellationToken).ConfigureAwait(false);
    }

    private static ConnectorBindingSet[] Latest(IEnumerable<ConnectorBindingSet> values) => values
        .GroupBy(value => value.EnvironmentId)
        .Select(group => group.OrderByDescending(value => value.Revision).First())
        .OrderBy(value => value.EnvironmentId)
        .ToArray();
}
