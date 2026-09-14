using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;

string adminConnection = Required("M3_POSTGRES_ADMIN_CONNECTION");
string runtimePassword = Required("M3_POSTGRES_RUNTIME_PASSWORD");
string activationKeyText = Required("M3_ACTIVATION_HMAC_BASE64");
string outputPath = Required("M3_PROVISIONING_OUTPUT");
string? adminApiPassword = Optional("M5_POSTGRES_ADMIN_API_PASSWORD");
using X509Certificate2 vendorCertificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(Required("M3_VENDOR_CLIENT_PFX_BASE64")), null, X509KeyStorageFlags.EphemeralKeySet);
using X509Certificate2 wrongVendorCertificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(Required("M3_WRONG_VENDOR_CLIENT_PFX_BASE64")), null, X509KeyStorageFlags.EphemeralKeySet);
byte[] activationKey;
try { activationKey = Convert.FromBase64String(activationKeyText); }
catch (FormatException) { throw new InvalidOperationException("M3 activation HMAC key must be Base64."); }
if (activationKey.Length < 32) throw new InvalidOperationException("M3 activation HMAC key must contain at least 256 bits.");

await EnsureRuntimeRoleAsync(adminConnection, runtimePassword).ConfigureAwait(false);
if (adminApiPassword is not null) await EnsureAdminRoleAsync(adminConnection, adminApiPassword).ConfigureAwait(false);
await using NpgsqlDataSource dataSource = NpgsqlDataSource.Create(adminConnection);
PostgresGatewayRegistry registry = new(dataSource);
PostgresConnectorConfigurationStore connectorStore = new(dataSource);
SystemGatewayClock clock = new();
GatewayProvisioningService provisioning = new(registry, clock, new EnrollmentSecurityOptions { ActivationHmacKey = activationKey });
string? independentOnboardingWorkflow = Optional("M3_INDEPENDENT_ONBOARDING_WORKFLOW");
if (independentOnboardingWorkflow is not null)
{
    if (independentOnboardingWorkflow is not "1" and not "2")
        throw new InvalidOperationException("M3_INDEPENDENT_ONBOARDING_WORKFLOW must be 1 or 2.");

    string workflow = independentOnboardingWorkflow;
    Guid isolatedTenantId = Guid.NewGuid();
    Guid isolatedApplicationId = Guid.NewGuid();
    Guid isolatedEnvironmentId = Guid.NewGuid();
    Guid isolatedInstallationId = Guid.NewGuid();
    const string isolatedConnectorId = "fse2-officialtest-validate-cda";
    ProvisionedActivation isolatedActivation = await provisioning.CreateInstallationAsync(
        new TenantRecord(isolatedTenantId, "same-nat-tenant-" + workflow, "Same NAT Tenant " + workflow, TenantStatus.Active, clock.UtcNow),
        new ApplicationRecord(isolatedApplicationId, "same-nat-application-" + workflow, "Same NAT Application " + workflow, ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
        new GatewayEnvironmentRecord(isolatedEnvironmentId, "same-nat-" + workflow, "Same NAT Environment " + workflow, false),
        isolatedInstallationId,
        "m3-provisioner",
        CancellationToken.None).ConfigureAwait(false);
    ProviderResourceCatalogRecord isolatedA1 = await RegisterFse2OfficialTestResourceAsync(
        isolatedEnvironmentId,
        "same-nat-" + workflow + "-a1",
        "Same NAT synthetic A1 " + workflow,
        "synthetic-vault://vault.m3.test/same-nat-" + workflow + "-a1",
        vendorCertificate).ConfigureAwait(false);
    ProviderResourceCatalogRecord isolatedS1 = await RegisterFse2OfficialTestResourceAsync(
        isolatedEnvironmentId,
        "same-nat-" + workflow + "-s1",
        "Same NAT synthetic S1 " + workflow,
        "synthetic-vault://vault.m3.test/same-nat-" + workflow + "-s1",
        wrongVendorCertificate).ConfigureAwait(false);

    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
    await File.WriteAllBytesAsync(outputPath, JsonSerializer.SerializeToUtf8Bytes(new
    {
        schemaVersion = 1,
        workflow,
        connectorId = isolatedConnectorId,
        tenantId = isolatedTenantId,
        applicationId = isolatedApplicationId,
        environmentId = isolatedEnvironmentId,
        installationId = isolatedInstallationId,
        activationCodeId = isolatedActivation.ActivationCodeId,
        activationCode = isolatedActivation.ActivationCode,
        expiresAtUtc = isolatedActivation.ExpiresAt,
        a1 = ProviderAuthority(isolatedA1),
        s1 = ProviderAuthority(isolatedS1)
    }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true })).ConfigureAwait(false);
    Console.WriteLine(JsonSerializer.Serialize(new { status = "provisioned", workflow, installationId = isolatedInstallationId, activationCodeId = isolatedActivation.ActivationCodeId }));
    return 0;
}

Guid tenantId = Guid.NewGuid();
Guid applicationId = Guid.NewGuid();
Guid environmentId = OptionalGuid("M3_PRIMARY_ENVIRONMENT_ID") ?? Guid.NewGuid();
Guid installationId = Guid.NewGuid();
ProvisionedActivation activation = await provisioning.CreateInstallationAsync(
    new TenantRecord(tenantId, "m3-tenant", "M3 Synthetic Tenant", TenantStatus.Active, clock.UtcNow),
    new ApplicationRecord(applicationId, "m3-legacy", "M3 Legacy Simulator", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
    new GatewayEnvironmentRecord(environmentId, "m3", "M3 Deterministic", false),
    installationId,
    "m3-provisioner",
    CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), installationId, tenantId, "m3-vendor", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), installationId, tenantId, "sample-secure-service", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
Guid directInstallationId = Guid.NewGuid();
GatewayAuditEvent directInstallationAudit = new(
    Guid.NewGuid(),
    clock.UtcNow,
    tenantId,
    "administrator",
    "m3-provisioner",
    "installation.create",
    "installation",
    directInstallationId.ToString("D"),
    Guid.NewGuid(),
    "success",
    "BGW-INSTALLATION-CREATED",
    new Dictionary<string, string> { ["installationKind"] = InstallationKind.Direct.ToString() });
ProvisionedActivation directActivation = await provisioning.CreateAdminInstallationAsync(
    new InstallationRecord(
        directInstallationId,
        tenantId,
        applicationId,
        environmentId,
        InstallationStatus.Pending,
        null,
        clock.UtcNow,
        InstallationKind: InstallationKind.Direct,
        UpdatedAt: clock.UtcNow),
    "m3-provisioner",
    directInstallationAudit,
    CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), directInstallationId, tenantId, "sample-secure-service", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
Guid securityInstallationId = Guid.NewGuid();
Guid securityTenantId = Guid.NewGuid();
Guid securityApplicationId = Guid.NewGuid();
Guid securityEnvironmentId = OptionalGuid("M3_SECURITY_ENVIRONMENT_ID") ?? Guid.NewGuid();
ProvisionedActivation securityActivation = await provisioning.CreateInstallationAsync(
    new TenantRecord(securityTenantId, "m3-security-tenant", "M3 Security Driver Tenant", TenantStatus.Active, clock.UtcNow),
    new ApplicationRecord(securityApplicationId, "m3-security-driver", "M3 Security Driver", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
    new GatewayEnvironmentRecord(securityEnvironmentId, "m3-security", "M3 Security Tests", false),
    securityInstallationId,
    "m3-provisioner",
    CancellationToken.None).ConfigureAwait(false);
string[] securityGrantedOperations = ["submit", "loopback", "private", "metadata", "redirect", "wrong-certificate"];
foreach (string operation in securityGrantedOperations)
    await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), securityInstallationId, securityTenantId, "m3-vendor", operation, true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);

object? fse2OfficialTest = null;
if (Optional("M3_FSE2_OFFICIALTEST_SYNTHETIC_BOOTSTRAP") is "1" or "current-spec")
{
    bool currentSpec = Optional("M3_FSE2_OFFICIALTEST_SYNTHETIC_BOOTSTRAP") == "current-spec";
    ProviderResourceCatalogRecord a1 = await RegisterFse2OfficialTestResourceAsync(
        securityEnvironmentId,
        "fse2-officialtest-a1",
        "FSE2 OfficialTest synthetic A1",
        "synthetic-vault://vault.m3.test/fse2-officialtest-a1",
        vendorCertificate, currentSpec).ConfigureAwait(false);
    ProviderResourceCatalogRecord s1 = await RegisterFse2OfficialTestResourceAsync(
        securityEnvironmentId,
        "fse2-officialtest-s1",
        "FSE2 OfficialTest synthetic S1",
        "synthetic-vault://vault.m3.test/fse2-officialtest-s1",
        wrongVendorCertificate, currentSpec).ConfigureAwait(false);
    fse2OfficialTest = new
    {
        tenantId = securityTenantId,
        installationId = securityInstallationId,
        environmentId = securityEnvironmentId,
        a1 = ProviderAuthority(a1),
        s1 = ProviderAuthority(s1)
    };
}
await using AdminPostgresDataSource adminDataSource = new(adminConnection);
PostgresAdminSecurityStore adminSecurity = new(adminDataSource);
AdminPrincipalRecord provisionerEditor = await adminSecurity.EnsurePrincipalAsync(
    new("https://provisioner.synthetic.invalid", "m3-editor", "M3 synthetic editor", null),
    CancellationToken.None).ConfigureAwait(false);
AdminPrincipalRecord provisionerApprover = await adminSecurity.EnsurePrincipalAsync(
    new("https://provisioner.synthetic.invalid", "m3-approver", "M3 synthetic approver", null),
    CancellationToken.None).ConfigureAwait(false);
ConnectorDefinitionValidator connectorValidator = new();
await PublishConnectorAsync(M3VendorDefinition(), securityOperations: true).ConfigureAwait(false);
string sampleConnectorPath = Path.Combine(AppContext.BaseDirectory, "sample-secure-service.connector.json");
using JsonDocument sampleConnectorDocument = JsonDocument.Parse(await File.ReadAllBytesAsync(sampleConnectorPath).ConfigureAwait(false));
VerifyCanonicalSampleDefinition(sampleConnectorDocument.RootElement);
PublishedConnectorMetadata sampleConnector = await PublishConnectorAsync(sampleConnectorDocument.RootElement, securityOperations: false).ConfigureAwait(false);

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
byte[] document = JsonSerializer.SerializeToUtf8Bytes(new
{
    schemaVersion = 1,
    tenantId,
    applicationId,
    environmentId,
    installationId,
    activationCodeId = activation.ActivationCodeId,
    activationCode = activation.ActivationCode,
    expiresAtUtc = activation.ExpiresAt,
    directInstallationId,
    directActivationCodeId = directActivation.ActivationCodeId,
    directActivationCode = directActivation.ActivationCode,
    directExpiresAtUtc = directActivation.ExpiresAt,
    securityInstallationId,
    securityTenantId,
    securityActivationCodeId = securityActivation.ActivationCodeId,
    securityActivationCode = securityActivation.ActivationCode,
    securityExpiresAtUtc = securityActivation.ExpiresAt,
    sampleConnector,
    fse2OfficialTest
}, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
await File.WriteAllBytesAsync(outputPath, document).ConfigureAwait(false);
Console.WriteLine(JsonSerializer.Serialize(new { status = "provisioned", installationId, activationCodeId = activation.ActivationCodeId }));
return 0;

async Task<PublishedConnectorMetadata> PublishConnectorAsync(JsonElement definition, bool securityOperations)
{
    ValidatedConnectorDefinition validated = connectorValidator.ValidateRequired(definition);
    string connectorId = definition.GetProperty("connectorId").GetString() ?? throw new InvalidOperationException("M3_CONNECTOR_ID_INVALID");
    string version = definition.GetProperty("version").GetString() ?? throw new InvalidOperationException("M3_CONNECTOR_VERSION_INVALID");
    string editor = provisionerEditor.Id.ToString("D");
    ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, version, "1.0", ConnectorVersionState.Draft, validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), editor, clock.UtcNow, 1), CancellationToken.None).ConfigureAwait(false);
    ConnectorVersionRecord validatedRecord = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    Dictionary<string, Uri> endpoints = securityOperations
        ? new(StringComparer.Ordinal)
        {
            ["vendor"] = new("https://vendor.m3.test:8443/"),
            ["loopback"] = new("https://127.0.0.1/"),
            ["private"] = new("https://172.29.44.7/"),
            ["metadata"] = new("https://169.254.169.254/")
        }
        : new(StringComparer.Ordinal) { ["sample-vendor-endpoint"] = new("https://vendor.m3.test:8443/") };
    Guid selectedEnvironment = securityOperations ? securityEnvironmentId : environmentId;
    string catalogPrefix = securityOperations ? "security-" : string.Empty;
    ProviderResourceCatalogRecord secretResource = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-api-key", ProviderResourceType.Secret, "synthetic-vault://vault.m3.test/vendor-api-key", null, null).ConfigureAwait(false);
    ProviderResourceCatalogRecord certificateResource = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-client-certificate", vendorCertificate, 1).ConfigureAwait(false);
    string secretBinding = securityOperations ? "vendor-api-key" : "sample-vendor-api-key";
    string certificateBinding = securityOperations ? "vendor-client-certificate" : "sample-vendor-client-certificate";
    Dictionary<string, ProviderResourceBinding> secrets = new(StringComparer.Ordinal) { [secretBinding] = Binding(secretResource) };
    Dictionary<string, ProviderResourceBinding> certificates = new(StringComparer.Ordinal) { [certificateBinding] = Binding(certificateResource) };
    if (securityOperations)
    {
        ProviderResourceCatalogRecord wrongCertificate = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-wrong-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-wrong-client-certificate", wrongVendorCertificate, 1).ConfigureAwait(false);
        certificates.Add("vendor-wrong-client-certificate", Binding(wrongCertificate));
    }
    string checksum = ConnectorBindingDigests.Revision(draft.Id, selectedEnvironment, endpoints, secrets, certificates);
    _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, selectedEnvironment, endpoints, secrets, certificates, 0, checksum, ConnectorBindingState.Draft, clock.UtcNow, editor), null, Guid.NewGuid(), CancellationToken.None).ConfigureAwait(false);
    if (!securityOperations)
    {
        ProviderResourceCatalogRecord securitySecret = await RegisterResourceAsync(securityEnvironmentId, connectorId, "security-sample-vendor-api-key", ProviderResourceType.Secret, "synthetic-vault://vault.m3.test/vendor-api-key", null, null).ConfigureAwait(false);
        ProviderResourceCatalogRecord securityCertificate = await RegisterResourceAsync(securityEnvironmentId, connectorId, "security-sample-vendor-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-client-certificate", vendorCertificate, 1).ConfigureAwait(false);
        Dictionary<string, ProviderResourceBinding> securitySecrets = new(StringComparer.Ordinal) { ["sample-vendor-api-key"] = Binding(securitySecret) };
        Dictionary<string, ProviderResourceBinding> securityCertificates = new(StringComparer.Ordinal) { ["sample-vendor-client-certificate"] = Binding(securityCertificate) };
        string securityChecksum = ConnectorBindingDigests.Revision(draft.Id, securityEnvironmentId, endpoints, securitySecrets, securityCertificates);
        _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, securityEnvironmentId, endpoints, securitySecrets, securityCertificates, 0, securityChecksum, ConnectorBindingState.Draft, clock.UtcNow, editor), null, Guid.NewGuid(), CancellationToken.None).ConfigureAwait(false);
    }
    byte[] bindingDigest = await connectorStore.GetBindingBundleDigestAsync(draft.Id, CancellationToken.None).ConfigureAwait(false);
    ConnectorApprovalRecord approvalRequest = await adminSecurity.RequestApprovalAsync(draft, bindingDigest, provisionerEditor.Id, Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    _ = await adminSecurity.ApproveAsync(approvalRequest.Id, draft.Id, draft.ChecksumSha256, bindingDigest, draft.CreatedBy, provisionerApprover.Id, null, Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    ConnectorVersionRecord published = await connectorStore.PublishApprovedAsync(draft.Id, bindingDigest, validatedRecord.RowVersion, 0, provisionerApprover.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    ConnectorVersionRecord stored = await connectorStore.GetVersionAsync(connectorId, version, CancellationToken.None).ConfigureAwait(false)
        ?? throw new InvalidOperationException("M3_CONNECTOR_PUBLISHED_MISSING");
    ValidatedConnectorDefinition storedValidated = connectorValidator.ParseStored(stored.CanonicalJson, stored.ChecksumSha256);
    PublishedConnectorSnapshot snapshot = await connectorStore.GetPublishedSnapshotAsync(connectorId, selectedEnvironment, null, CancellationToken.None).ConfigureAwait(false)
        ?? throw new InvalidOperationException("M3_CONNECTOR_PUBLISHED_SNAPSHOT_MISSING");
    string[] expectedEndpoints = securityOperations ? ["vendor", "loopback", "private", "metadata"] : ["sample-vendor-endpoint"];
    string[] expectedSecrets = securityOperations ? ["vendor-api-key"] : ["sample-vendor-api-key"];
    string[] expectedCertificates = securityOperations ? ["vendor-client-certificate", "vendor-wrong-client-certificate"] : ["sample-vendor-client-certificate"];
    if (published.State != ConnectorVersionState.Published || stored.State != ConnectorVersionState.Published || snapshot.Version.State != ConnectorVersionState.Published ||
        !string.Equals(storedValidated.ChecksumSha256, validated.ChecksumSha256, StringComparison.Ordinal) ||
        !stored.ChecksumSha256.AsSpan().SequenceEqual(Convert.FromHexString(validated.ChecksumSha256)) ||
        !snapshot.Version.ChecksumSha256.AsSpan().SequenceEqual(stored.ChecksumSha256) ||
        !ExactKeys(snapshot.Bindings.Endpoints, expectedEndpoints) ||
        !ExactKeys(snapshot.Bindings.SecretResources, expectedSecrets) ||
        !ExactKeys(snapshot.Bindings.CertificateResources, expectedCertificates))
        throw new InvalidOperationException("M3_CONNECTOR_PUBLISHED_DRIFT");
    return new(connectorId, version, validated.ChecksumSha256, "Published", expectedEndpoints, expectedSecrets, expectedCertificates);
}

static bool ExactKeys<T>(IReadOnlyDictionary<string, T> values, string[] expected) =>
    values.Count == expected.Length && expected.All(values.ContainsKey);

static void VerifyCanonicalSampleDefinition(JsonElement definition)
{
    if (!string.Equals(definition.GetProperty("connectorId").GetString(), "sample-secure-service", StringComparison.Ordinal) ||
        !string.Equals(definition.GetProperty("version").GetString(), "1.0.0", StringComparison.Ordinal))
        throw new InvalidOperationException("M3_CANONICAL_SAMPLE_IDENTITY_INVALID");
    JsonElement bindings = definition.GetProperty("bindings");
    string[] endpoints = bindings.GetProperty("endpoints").EnumerateArray().Select(value => value.GetProperty("name").GetString() ?? string.Empty).ToArray();
    JsonElement[] secrets = bindings.GetProperty("secrets").EnumerateArray().ToArray();
    string[] secretNames = secrets.Where(value => string.Equals(value.GetProperty("kind").GetString(), "opaque", StringComparison.Ordinal)).Select(value => value.GetProperty("name").GetString() ?? string.Empty).ToArray();
    string[] certificateNames = secrets.Where(value => string.Equals(value.GetProperty("kind").GetString(), "clientCertificate", StringComparison.Ordinal)).Select(value => value.GetProperty("name").GetString() ?? string.Empty).ToArray();
    if (!endpoints.SequenceEqual(["sample-vendor-endpoint"], StringComparer.Ordinal) ||
        !secretNames.SequenceEqual(["sample-vendor-api-key"], StringComparer.Ordinal) ||
        !certificateNames.SequenceEqual(["sample-vendor-client-certificate"], StringComparer.Ordinal))
        throw new InvalidOperationException("M3_CANONICAL_SAMPLE_BINDINGS_INVALID");
}

static JsonElement M3VendorDefinition() => JsonSerializer.SerializeToElement(new
{
    schemaVersion = "1.0",
    connectorId = "m3-vendor",
    version = "3.0.0-m3",
    displayName = "M3 Synthetic Vendor",
    bindings = new
    {
        endpoints = new[] { new { name = "vendor" }, new { name = "loopback" }, new { name = "private" }, new { name = "metadata" } },
        secrets = new[] { new { name = "vendor-api-key", kind = "opaque" }, new { name = "vendor-client-certificate", kind = "clientCertificate" }, new { name = "vendor-wrong-client-certificate", kind = "clientCertificate" } }
    },
    operations = new[]
    {
        Operation("submit", "vendor", "/vendor/orders", "apiKeyAndMtls", "vendor-client-certificate"),
        Operation("loopback", "loopback", "/vendor/orders", "none", null),
        Operation("private", "private", "/vendor/orders", "none", null),
        Operation("metadata", "metadata", "/latest/meta-data/", "none", null),
        Operation("redirect", "vendor", "/vendor/redirect", "apiKeyAndMtls", "vendor-client-certificate"),
        Operation("wrong-certificate", "vendor", "/vendor/orders", "apiKeyAndMtls", "vendor-wrong-client-certificate")
    }
});

async Task<ProviderResourceCatalogRecord> RegisterResourceAsync(Guid environment, string connector, string resourceId, ProviderResourceType type, string providerReference, X509Certificate2? certificate, long? metadataRevision)
{
    CertificatePublicMetadata? metadata = certificate is null ? null : CertificateMetadata(certificate);
    return await connectorStore.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic-vault", "Synthetic vault", "synthetic-vault", resourceId, type, resourceId, environment, connector, "*", providerReference, ProviderResourceStatus.Active, null, 0, metadataRevision, metadata, string.Empty, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
}

async Task<ProviderResourceCatalogRecord> RegisterFse2OfficialTestResourceAsync(
    Guid environment,
    string resourceId,
    string displayName,
    string providerReference,
    X509Certificate2 certificate,
    bool currentSpec = false) =>
    await connectorStore.RegisterProviderResourceAsync(new(
        Guid.NewGuid(),
        "synthetic-vault",
        "Synthetic vault",
        "synthetic-vault",
        resourceId,
        ProviderResourceType.ClientCertificate,
        displayName,
        environment,
        currentSpec ? "fse2-organization-current-spec" : "fse2-officialtest-validate-cda",
        currentSpec ? "*" : "validate-cda",
        providerReference,
        ProviderResourceStatus.Active,
        "1",
        0,
        1,
        CertificateMetadata(certificate),
        string.Empty,
        clock.UtcNow), CancellationToken.None).ConfigureAwait(false);

static object ProviderAuthority(ProviderResourceCatalogRecord resource) => new
{
    resource.ProviderId,
    resource.ResourceId,
    resource.Version,
    catalogRevision = resource.Revision,
    resource.PublicMetadataRevision
};

static ProviderResourceBinding Binding(ProviderResourceCatalogRecord resource) => new(resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId, resource.ResourceType, resource.DisplayName, resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope, resource.Version, resource.Revision, resource.PublicMetadataRevision, resource.CertificateMetadata, resource.ChecksumSha256);

static CertificatePublicMetadata CertificateMetadata(X509Certificate2 certificate)
{
    using RSA? rsa = certificate.GetRSAPublicKey(); using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
    byte[] subjectPublicKeyInfo = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo()
        ?? throw new InvalidOperationException("M3 certificate public key is unsupported.");
    string? subjectCommonName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
    return new(
        Convert.ToHexString(SHA256.HashData(certificate.RawData)),
        certificate.Subject,
        certificate.Issuer,
        certificate.NotBefore,
        certificate.NotAfter,
        rsa is not null ? "RSA" : "ECDSA",
        rsa?.KeySize ?? ecdsa?.KeySize ?? 0,
        certificate.SerialNumber,
        Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)),
        subjectCommonName);
}

static object Operation(string operationId, string endpointBinding, string path, string authentication, string? certificateBinding)
{
    object auth = authentication == "none"
        ? new { kind = "none" }
        : (object)new { kind = authentication, secretBinding = "vendor-api-key", headerName = "X-Vendor-Api-Key", certificateBinding };
    return new
    {
        operationId,
        endpointBinding,
        method = "POST",
        path,
        request = new { contentType = "application/json", maximumBytes = 1048576 },
        response = new { maximumBytes = 1048576 },
        authentication = auth,
        timeoutMs = 30000,
        redirectPolicy = "deny",
        allowedClientHeaders = Array.Empty<string>(),
        idempotent = false,
        maximumRetries = 0
    };
}

static string Required(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"{name} is required.");
    return value;
}

static string? Optional(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (value is not null && (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n'))) throw new InvalidOperationException($"{name} is invalid.");
    return value;
}

static Guid? OptionalGuid(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (value is null || value.Length == 0) return null;
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n'))
        throw new InvalidOperationException($"{name} is invalid.");
    if (!Guid.TryParseExact(value, "D", out Guid parsed) || parsed == Guid.Empty)
        throw new InvalidOperationException($"{name} must be a non-empty canonical GUID.");
    return parsed;
}

static async Task EnsureRuntimeRoleAsync(string connectionString, string password)
{
    await using NpgsqlConnection connection = new(connectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    await using NpgsqlCommand quote = new("SELECT quote_literal($1)", connection);
    quote.Parameters.AddWithValue(password);
    string quotedPassword = (string)(await quote.ExecuteScalarAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Cannot quote runtime credential."));
    string sql = $"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='m3_gateway_runtime') THEN CREATE ROLE m3_gateway_runtime LOGIN; END IF; END $$; ALTER ROLE m3_gateway_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION LOGIN PASSWORD {quotedPassword}; GRANT gateway_runtime TO m3_gateway_runtime;";
    await using NpgsqlCommand command = new(sql, connection);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
}

static async Task EnsureAdminRoleAsync(string connectionString, string password)
{
    await using NpgsqlConnection connection = new(connectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    await using NpgsqlCommand quote = new("SELECT quote_literal($1)", connection);
    quote.Parameters.AddWithValue(password);
    string quotedPassword = (string)(await quote.ExecuteScalarAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Cannot quote Admin credential."));
    string sql = $"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='m5_gateway_admin') THEN CREATE ROLE m5_gateway_admin LOGIN; END IF; END $$; ALTER ROLE m5_gateway_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION LOGIN PASSWORD {quotedPassword}; GRANT gateway_admin TO m5_gateway_admin;";
    await using NpgsqlCommand command = new(sql, connection);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
}

file sealed record PublishedConnectorMetadata(
    string ConnectorId,
    string Version,
    string ChecksumSha256,
    string State,
    string[] EndpointBindings,
    string[] SecretBindings,
    string[] CertificateBindings);
