using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.TestDiagnostics;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class TypedSessionHandshakeRealHttpIntegrationTests
{
    private const string TypedNamespace = "urn:synthetic:typed-session";
    private const string LegacyNamespace = "urn:synthetic:session";
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_IT_Real_HTTPS_typed_handshake_direct_or_external_admission_promotes_and_supports_session_use(bool externalAdmission)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        const string externalCandidate = "synthetic-external-session";
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2), externalAdmission, externalCandidate),
            certificates.Server, TestContext.Current.CancellationToken);

        Uri baseEndpoint = new(server.Endpoint, "/");
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        TypedValidator validator = new();
        TypedSessionHandshakeAdapterRegistry registry = new([new RequestAdapter()], [new ResponseAdapter()], [validator]);
        SnapshotFixture snapshot = new(baseEndpoint);
        SystemGatewayClock clock = new();
        PublishedTypedSessionHandshakeResolver authority = new(snapshot.ResolveAsync, registry, clock, new());
        SoapSessionClient client = new(new FixedSecrets(), new LoopbackResolver(), transport, clock, new MatchingStampProvider(), new LoopbackAllowance(baseEndpoint.DnsSafeHost));
        AuthorizedGatewayInvocation invocation = snapshot.Invocation(clock);
        ResolvedTypedSessionHandshake resolved = await authority.ResolveAsync(invocation, new("typed-session"), TestContext.Current.CancellationToken);

        TypedSessionHandshakeResult result = await client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        if (externalAdmission)
        {
            Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, result.Kind);
            ExternalAdmissionPresentation presentation = client.ResolveAdmissionPresentation(invocation.Principal, result.AdmissionIntent!.Reference);
            result = await client.CompleteExternalAdmissionAsync(resolved, presentation,
                ExternalSessionCandidate.Create(Encoding.UTF8.GetBytes(externalCandidate)), TestContext.Current.CancellationToken);
            Assert.Equal(1, server.Counters.ValidateSession);
        }
        else
        {
            Assert.Equal(0, server.Counters.ValidateSession);
        }

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, result.Kind);
        SoapBusinessResult business = await client.InvokeAsync(resolved.State.ExecutionContext, resolved.State.Endpoint, BusinessProfile(),
            new Dictionary<string, string> { ["payload"] = "normal" }, result.Session, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", business.Values["result"]);
        Assert.Equal(1, server.Counters.CreateSession);
        Assert.Equal(1, server.Counters.Business);
    }

    [Fact]
    public async Task Wave1_IT_Internal_composition_store_authorizer_registry_and_real_restricted_HTTPS_complete_external_admission()
    {
        using TimeoutObservation observation = new("soap");
        await using TypedRuntimeApiFactory factory = new();
        using HttpClient api = factory.CreateClient();
        TypedSessionHandshakeAdapterRegistry adapters = factory.Services.GetRequiredService<TypedSessionHandshakeAdapterRegistry>();
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        IGatewayRegistry gatewayRegistry = factory.Services.GetRequiredService<IGatewayRegistry>();
        IGatewayClock clock = factory.Services.GetRequiredService<IGatewayClock>();
        Assert.NotNull(factory.Services.GetRequiredService<TypedSessionHandshakeRuntime>());
        observation.Mark("factory-ready");

        using CertificateFixture certificates = CertificateFixture.Create();
        const string externalCandidate = "production-path-external-session";
        observation.Mark("https-server-start");
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2), true, externalCandidate),
            certificates.Server, TestContext.Current.CancellationToken);

        observation.Mark("https-server-started");
        string suffix = Guid.NewGuid().ToString("N");
        string connectorSlug = "typed-production-" + suffix;
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        DateTimeOffset now = clock.UtcNow;
        await gatewayRegistry.AddTenantAsync(new(tenantId, "tw1-t-" + suffix, "Typed tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await gatewayRegistry.AddApplicationAsync(new(applicationId, "tw1-a-" + suffix, "Typed application", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await gatewayRegistry.AddEnvironmentAsync(new(environmentId, "tw1-e-" + suffix[..20], "Typed environment", false), TestContext.Current.CancellationToken);
        await gatewayRegistry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
        await gatewayRegistry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorSlug, "session-bootstrap", true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);

        ProviderResourceCatalogRecord username = await store.RegisterProviderResourceAsync(Resource("username-" + suffix, "synthetic://typed-username", connectorSlug, environmentId, now), TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord password = await store.RegisterProviderResourceAsync(Resource("password-" + suffix, "synthetic://typed-password", connectorSlug, environmentId, now), TestContext.Current.CancellationToken);
        using JsonDocument definition = JsonDocument.Parse(ProductionDefinition(connectorSlug));
        ConnectorDefinitionValidator definitionValidator = new();
        ConnectorValidationResult validation = definitionValidator.Validate(definition.RootElement);
        Assert.True(validation.Valid, string.Join(';', validation.Issues.Select(issue => issue.Code + "@" + issue.Location)));
        ValidatedConnectorDefinition validatedDefinition = definitionValidator.ValidateRequired(definition.RootElement);
        ConnectorVersionRecord draft = await store.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorSlug, "1.0.0", "1.0", ConnectorVersionState.Draft,
            validatedDefinition.CanonicalJson, Convert.FromHexString(validatedDefinition.ChecksumSha256), "editor", now, 0, null, null), TestContext.Current.CancellationToken);
        ConnectorVersionRecord validated = await store.MarkValidatedAsync(draft.Id, draft.RowVersion, now.AddSeconds(1), TestContext.Current.CancellationToken);
        Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal) { ["soap"] = new(server.Endpoint, "/") };
        Dictionary<string, ProviderResourceBinding> secrets = new(StringComparer.Ordinal)
        {
            ["username"] = Binding(username, "username"),
            ["password"] = Binding(password, "password")
        };
        string bindingChecksum = ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints, secrets, new Dictionary<string, ProviderResourceBinding>());
        _ = await store.PutBindingsAsync(new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints, secrets,
            new Dictionary<string, ProviderResourceBinding>(), 0, bindingChecksum, ConnectorBindingState.Draft, now.AddSeconds(2), "editor"),
            null, Guid.NewGuid(), TestContext.Current.CancellationToken);

        SystemRestrictedTransport transport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        SoapSessionClient sessions = new(new FixedSecrets(), new LoopbackResolver(), transport, clock,
            new PublishedSoapSessionResourceStampProvider(store), new LoopbackAllowance(server.Endpoint.DnsSafeHost));
        GatewayInvocationAuthorizer authorizer = new(gatewayRegistry, clock);
        PublishedTypedSessionHandshakeResolver publishedResolver = new(store, adapters, clock);
        TypedSessionHandshakeRuntime runtime = new(authorizer, publishedResolver, sessions);
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active,
            InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
        GatewayClientPrincipal principal = new(identity, Guid.NewGuid());

        SoapAuthException unpublished = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.AcquireAsync(principal, connectorSlug, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TYPED-AUTHORITY-REJECTED", unpublished.Code);
        Assert.Equal(0, server.Counters.CreateSession);

        _ = await store.PublishAsync(validated.Id, validated.RowVersion, 0, "approver", now.AddSeconds(3), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity ungrantedIdentity = identity with { InstallationId = Guid.NewGuid(), CredentialId = Guid.NewGuid() };
        GatewayException wrongGrant = await Assert.ThrowsAsync<GatewayException>(() => runtime.AcquireAsync(new(ungrantedIdentity, Guid.NewGuid()), connectorSlug,
            "session-bootstrap", "typed-session", TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHZ-OPERATION-DENIED", wrongGrant.Code);
        Assert.Equal(0, server.Counters.CreateSession);

        observation.Mark("acquire-start");
        TypedSessionHandshakeResult started = await runtime.AcquireAsync(principal, connectorSlug, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken);
        observation.Mark("acquire-completed");
        Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, started.Kind);
        foreach (RegisteredInstallationIdentity wrongIdentity in new[]
        {
            identity with { TenantId = Guid.NewGuid(), CredentialId = Guid.NewGuid() },
            identity with { ApplicationId = Guid.NewGuid(), CredentialId = Guid.NewGuid() },
            identity with { InstallationId = Guid.NewGuid(), CredentialId = Guid.NewGuid() }
        })
        {
            SoapAuthException wrongPrincipal = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.CompleteExternalAdmissionAsync(
                new(wrongIdentity, Guid.NewGuid()), started.AdmissionIntent!.Reference, Encoding.UTF8.GetBytes(externalCandidate), TestContext.Current.CancellationToken));
            Assert.Equal("SOAP-ADMISSION-INTENT-INVALID", wrongPrincipal.Code);
        }
        Assert.Equal(0, server.Counters.ValidateSession);
        observation.Mark("admission-start");
        TypedSessionHandshakeResult completed = await runtime.CompleteExternalAdmissionAsync(principal, started.AdmissionIntent!.Reference,
            Encoding.UTF8.GetBytes(externalCandidate), TestContext.Current.CancellationToken);
        observation.Mark("admission-completed");

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, completed.Kind);
        AuthorizedGatewayInvocation authorized = await authorizer.AuthorizeAsync(principal, connectorSlug, "session-bootstrap", TestContext.Current.CancellationToken);
        ResolvedTypedSessionHandshake current = await publishedResolver.ResolveAsync(authorized, new("typed-session"), TestContext.Current.CancellationToken);
        observation.Mark("business-start-30000ms-operation-deadline");
        SoapBusinessResult business;
        try
        {
            business = await sessions.InvokeAsync(current.State.ExecutionContext, current.State.Endpoint, BusinessProfile(),
                new Dictionary<string, string> { ["payload"] = "normal" }, completed.Session, TestContext.Current.CancellationToken);
            observation.Mark("business-completed");
        }
        finally
        {
            observation.Mark(server.Counters.Business > 0 ? "server-business-observed" : "server-business-not-observed");
        }
        Assert.Equal("accepted", business.Values["result"]);
        Assert.Equal(1, server.Counters.CreateSession);
        Assert.Equal(1, server.Counters.ValidateSession);
        Assert.Equal(1, server.Counters.Business);
    }

    [Fact]
    public async Task Wave1_IT_Internal_composition_runtime_denies_adapter_version_endpoint_and_resource_authority_changes_before_validation_network()
    {
        await using TypedRuntimeApiFactory factory = new();
        TypedSessionHandshakeAdapterRegistry adapters = factory.Services.GetRequiredService<TypedSessionHandshakeAdapterRegistry>();
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        IGatewayRegistry registry = factory.Services.GetRequiredService<IGatewayRegistry>();
        IGatewayClock clock = factory.Services.GetRequiredService<IGatewayClock>();
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2), true, "production-negative-candidate"),
            certificates.Server, TestContext.Current.CancellationToken);

        string suffix = Guid.NewGuid().ToString("N");
        Guid tenantId = Guid.NewGuid();
        Guid applicationId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        Guid installationId = Guid.NewGuid();
        DateTimeOffset now = clock.UtcNow;
        await registry.AddTenantAsync(new(tenantId, "tw1n-t-" + suffix, "Typed negative tenant", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "tw1n-a-" + suffix, "Typed negative application", ApplicationStatus.Active, "1.0.0", null, now), TestContext.Current.CancellationToken);
        await registry.AddEnvironmentAsync(new(environmentId, "tw1n-e-" + suffix[..20], "Typed negative environment", false), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active,
            InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
        GatewayClientPrincipal principal = new(identity, Guid.NewGuid());

        SystemRestrictedTransport transport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        SoapSessionClient sessions = new(new FixedSecrets(), new LoopbackResolver(), transport, clock,
            new PublishedSoapSessionResourceStampProvider(store), new LoopbackAllowance(server.Endpoint.DnsSafeHost));
        TypedSessionHandshakeRuntime runtime = new(new GatewayInvocationAuthorizer(registry, clock),
            new PublishedTypedSessionHandshakeResolver(store, adapters, clock), sessions);
        int sequence = 0;

        async Task<(string Connector, ConnectorVersionRecord Published, ConnectorBindingSet Binding, Dictionary<string, ProviderResourceBinding> Secrets, ProviderResourceCatalogRecord Username)> CreateCaseAsync(
            string marker, Func<string, string>? mutateDefinition = null)
        {
            string connector = $"typed-negative-{marker}-{suffix}";
            await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connector, "session-bootstrap", true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
            ProviderResourceCatalogRecord username = await store.RegisterProviderResourceAsync(
                Resource($"username-{marker}-{suffix}", $"synthetic://typed-username-{marker}", connector, environmentId, now), TestContext.Current.CancellationToken);
            ProviderResourceCatalogRecord password = await store.RegisterProviderResourceAsync(
                Resource($"password-{marker}-{suffix}", $"synthetic://typed-password-{marker}", connector, environmentId, now), TestContext.Current.CancellationToken);
            Dictionary<string, ProviderResourceBinding> secrets = new(StringComparer.Ordinal)
            {
                ["username"] = Binding(username, "username"),
                ["password"] = Binding(password, "password")
            };
            (ConnectorVersionRecord published, ConnectorBindingSet binding) = await PublishVersionAsync(connector, "1.0.0",
                mutateDefinition?.Invoke(ProductionDefinition(connector)) ?? ProductionDefinition(connector), secrets);
            return (connector, published, binding, secrets, username);
        }

        async Task<(ConnectorVersionRecord Published, ConnectorBindingSet Binding)> PublishVersionAsync(
            string connector, string version, string definitionJson, Dictionary<string, ProviderResourceBinding> secrets, long expectedPublicationRevision = 0)
        {
            using JsonDocument definition = JsonDocument.Parse(definitionJson);
            ValidatedConnectorDefinition required = new ConnectorDefinitionValidator().ValidateRequired(definition.RootElement);
            DateTimeOffset at = now.AddMilliseconds(++sequence);
            ConnectorVersionRecord draft = await store.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connector, version, "1.0", ConnectorVersionState.Draft,
                required.CanonicalJson, Convert.FromHexString(required.ChecksumSha256), "editor", at, 0, null, null), TestContext.Current.CancellationToken);
            ConnectorVersionRecord validated = await store.MarkValidatedAsync(draft.Id, draft.RowVersion, at, TestContext.Current.CancellationToken);
            Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal) { ["soap"] = new(server.Endpoint, "/") };
            string checksum = ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints, secrets, new Dictionary<string, ProviderResourceBinding>());
            ConnectorBindingSet binding = await store.PutBindingsAsync(new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints, secrets,
                new Dictionary<string, ProviderResourceBinding>(), 0, checksum, ConnectorBindingState.Draft, at, "editor"), null, Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionRecord published = await store.PublishAsync(validated.Id, validated.RowVersion, expectedPublicationRevision, "approver", at, TestContext.Current.CancellationToken);
            return (published, binding with { State = ConnectorBindingState.Active });
        }

        foreach ((string marker, Func<string, string> mutate) in new[]
        {
            ("unknown", (Func<string, string>)(definition => definition.Replace("synthetic-session-validator", "unknown-session-validator", StringComparison.Ordinal))),
            ("wrong-type", definition => definition.Replace("compiled-typed-validator", "wrong-typed-validator", StringComparison.Ordinal))
        })
        {
            var adapterCase = await CreateCaseAsync(marker, mutate);
            SoapAuthException unavailable = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.AcquireAsync(
                principal, adapterCase.Connector, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken));
            Assert.Equal("SOAP-TYPED-ADAPTER-UNAVAILABLE", unavailable.Code);
            Assert.Equal(0, server.Counters.CreateSession);
        }

        var staleVersion = await CreateCaseAsync("stale-version");
        TypedSessionHandshakeResult staleIntent = await runtime.AcquireAsync(principal, staleVersion.Connector, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken);
        string versionTwo = ProductionDefinition(staleVersion.Connector).Replace("\"version\":\"1.0.0\"", "\"version\":\"2.0.0\"", StringComparison.Ordinal);
        _ = await PublishVersionAsync(staleVersion.Connector, "2.0.0", versionTwo, staleVersion.Secrets, 1);
        SoapAuthException stale = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.CompleteExternalAdmissionAsync(
            principal, staleIntent.AdmissionIntent!.Reference, "production-negative-candidate"u8.ToArray(), TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-ADMISSION-INTENT-INVALID", stale.Code);

        var endpointChange = await CreateCaseAsync("endpoint-change");
        TypedSessionHandshakeResult endpointIntent = await runtime.AcquireAsync(principal, endpointChange.Connector, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken);
        Dictionary<string, Uri> changedEndpoints = new(StringComparer.Ordinal) { ["soap"] = new(server.Endpoint, "/changed") };
        string changedChecksum = ConnectorBindingDigests.Revision(endpointChange.Published.Id, environmentId, changedEndpoints, endpointChange.Secrets,
            new Dictionary<string, ProviderResourceBinding>());
        _ = await store.PutBindingsAsync(endpointChange.Binding with { Id = Guid.NewGuid(), Endpoints = changedEndpoints, ChecksumSha256 = changedChecksum,
            State = ConnectorBindingState.Active, UpdatedAt = now.AddMilliseconds(++sequence) }, endpointChange.Binding.Revision, Guid.NewGuid(), TestContext.Current.CancellationToken);
        SoapAuthException endpointStale = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.CompleteExternalAdmissionAsync(
            principal, endpointIntent.AdmissionIntent!.Reference, "production-negative-candidate"u8.ToArray(), TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-ADMISSION-INTENT-INVALID", endpointStale.Code);

        var disabledResource = await CreateCaseAsync("disabled-resource");
        TypedSessionHandshakeResult disabledIntent = await runtime.AcquireAsync(principal, disabledResource.Connector, "session-bootstrap", "typed-session", TestContext.Current.CancellationToken);
        _ = await store.RegisterProviderResourceAsync(disabledResource.Username with { Id = Guid.NewGuid(), Status = ProviderResourceStatus.Disabled,
            Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = now.AddMilliseconds(++sequence) }, TestContext.Current.CancellationToken);
        SoapAuthException disabled = await Assert.ThrowsAsync<SoapAuthException>(() => runtime.CompleteExternalAdmissionAsync(
            principal, disabledIntent.AdmissionIntent!.Reference, "production-negative-candidate"u8.ToArray(), TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TYPED-AUTHORITY-REJECTED", disabled.Code);

        Assert.Equal(3, server.Counters.CreateSession);
        Assert.Equal(0, server.Counters.ValidateSession);
    }

    private static SoapSessionProfile BusinessProfile()
    {
        SoapOperationProfile login = new("unused-login", SoapEnvelopeVersion.Soap11, "urn:synthetic:Login",
            new("Login", LegacyNamespace), new("LoginResponse", LegacyNamespace));
        SoapOperationProfile business = new("session-bootstrap", SoapEnvelopeVersion.Soap11, "urn:synthetic:BusinessOperation",
            new("BusinessOperation", LegacyNamespace), new("BusinessOperationResponse", LegacyNamespace),
            [new("payload", new("Payload", LegacyNamespace))], [new("result", new("Result", LegacyNamespace))]);
        return new("typed-session", new("provider/username", "provider/password"), login, new("SessionId", LegacyNamespace),
            new("Session", LegacyNamespace), [business], TimeSpan.FromMinutes(5), []);
    }

    private static ProviderResourceCatalogRecord Resource(string resourceId, string providerReference, string connectorSlug, Guid environmentId, DateTimeOffset now) =>
        new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", resourceId, ProviderResourceType.Secret, resourceId,
            environmentId, connectorSlug, "session-bootstrap", providerReference, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now);

    private static ProviderResourceBinding Binding(ProviderResourceCatalogRecord resource, string displayName) =>
        new(resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId, resource.ResourceType, displayName,
            resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope, resource.Version, resource.Revision, resource.PublicMetadataRevision,
            resource.CertificateMetadata, resource.ChecksumSha256);

    internal static string ProductionDefinition(string connectorSlug) => $$"""
        {
          "schemaVersion":"1.0","connectorId":"{{connectorSlug}}","version":"1.0.0","displayName":"Typed production path",
          "bindings":{"endpoints":[{"name":"soap"}],"secrets":[{"name":"username","kind":"username"},{"name":"password","kind":"password"}]},
          "operations":[{
            "operationId":"session-bootstrap","endpointBinding":"soap","method":"POST","path":"/service",
            "request":{"contentType":"text/xml","maximumBytes":32768},"response":{"maximumBytes":32768},
            "authentication":{"kind":"basic","usernameBinding":"username","passwordBinding":"password"},
            "typedSessionHandshake":{
              "profileId":"typed-session","soapVersion":"1.1","action":"urn:synthetic:CreateSession",
              "requestElement":{"localName":"CreateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
              "responseElement":{"localName":"CreateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
              "requestAdapter":{"id":"synthetic-create-session-request","type":"compiled-typed-request"},
              "responseAdapter":{"id":"synthetic-create-session-response","type":"compiled-typed-response"},
              "sessionLifetimeSeconds":300,
              "externalAdmission":{
                "validator":{"id":"synthetic-session-validator","type":"compiled-typed-validator"},"endpointBinding":"soap","path":"/service",
                "soapVersion":"1.1","action":"urn:synthetic:ValidateSession",
                "requestElement":{"localName":"ValidateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
                "responseElement":{"localName":"ValidateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
                "intentLifetimeSeconds":60,"timeoutMs":5000,"maximumRequestBytes":32768,"maximumResponseBytes":32768
              }
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;

    private sealed class TypedRuntimeApiFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
        }
    }

    private sealed class RequestAdapter : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request";
        public string AdapterType => "compiled-typed-request";
        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
        {
            writer.WriteStartElement("s", "ClientContext", TypedNamespace);
            writer.WriteStartElement("s", "Identity", TypedNamespace);
            writer.WriteElementString("s", "Tenant", TypedNamespace, context.TenantId.ToString("D"));
            writer.WriteElementString("s", "Installation", TypedNamespace, context.InstallationId.ToString("D"));
            writer.WriteElementString("s", "Application", TypedNamespace, context.ApplicationId.ToString("D"));
            writer.WriteEndElement();
            writer.WriteStartElement("s", "Policy", TypedNamespace);
            writer.WriteElementString("s", "Profile", TypedNamespace, context.ProfileId);
            writer.WriteElementString("s", "PublishedChecksum", TypedNamespace, context.PublishedPolicyChecksum);
            writer.WriteEndElement();
            writer.WriteEndElement();
        }
    }

    private sealed class ResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";
        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
        {
            payload.ReadStartElement("CreateSessionResponse", TypedNamespace);
            payload.ReadStartElement("Result", TypedNamespace);
            string status = payload.ReadElementContentAsString("Status", TypedNamespace);
            TypedSessionHandshakeAdapterOutcome result;
            if (string.Equals(status, "issued", StringComparison.Ordinal))
            {
                payload.ReadStartElement("Session", TypedNamespace);
                string session = payload.ReadElementContentAsString("Value", TypedNamespace);
                DateTimeOffset expiry = DateTimeOffset.ParseExact(payload.ReadElementContentAsString("ExpiresAt", TypedNamespace), "O", CultureInfo.InvariantCulture);
                payload.ReadEndElement();
                result = TypedSessionHandshakeAdapterOutcome.Issued(session, expiry);
            }
            else if (string.Equals(status, "external_admission_required", StringComparison.Ordinal))
            {
                payload.ReadStartElement("Admission", TypedNamespace);
                if (!string.Equals(payload.ReadElementContentAsString("Provenance", TypedNamespace), "interactive_handoff", StringComparison.Ordinal)) throw new XmlException();
                payload.ReadEndElement();
                result = TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired();
            }
            else throw new XmlException();
            payload.ReadEndElement();
            payload.ReadEndElement();
            return result;
        }
    }

    private sealed class TypedValidator : ITypedExternalSessionValidationAdapter
    {
        public string AdapterId => "synthetic-session-validator";
        public string AdapterType => "compiled-typed-validator";

        public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
        {
            writer.WriteStartElement("s", "Candidate", TypedNamespace);
            writer.WriteElementString("s", "Provenance", TypedNamespace, "interactive_handoff");
            writer.WriteElementString("s", "OpaqueValue", TypedNamespace, Encoding.UTF8.GetString(context.SensitiveCandidate.Span));
            writer.WriteEndElement();
        }

        public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
        {
            payload.ReadStartElement("ValidateSessionResponse", TypedNamespace);
            payload.ReadStartElement("Validation", TypedNamespace);
            string status = payload.ReadElementContentAsString("Status", TypedNamespace);
            if (string.Equals(status, "rejected", StringComparison.Ordinal))
            {
                payload.ReadEndElement();
                payload.ReadEndElement();
                return ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Rejected);
            }
            if (!string.Equals(status, "valid", StringComparison.Ordinal)) throw new XmlException();
            DateTimeOffset expiry = DateTimeOffset.ParseExact(payload.ReadElementContentAsString("ExpiresAt", TypedNamespace), "O", CultureInfo.InvariantCulture);
            payload.ReadEndElement();
            payload.ReadEndElement();
            return ExternalSessionValidationResult.Valid(expiry);
        }
    }

    private sealed class SnapshotFixture
    {
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly PublishedConnectorSnapshot snapshot;

        internal SnapshotFixture(Uri baseEndpoint)
        {
            object definition = new
            {
                operations = new[] { new { operationId = "session-bootstrap", endpointBinding = "soap", method = "POST", path = "/service",
                    request = new { contentType = "text/xml", maximumBytes = 32_768 }, response = new { maximumBytes = 32_768 }, timeoutMs = 5_000,
                    authentication = new { kind = "basic", usernameBinding = "username", passwordBinding = "password" },
                    typedSessionHandshake = new { profileId = "typed-session", soapVersion = "1.1", action = "urn:synthetic:CreateSession",
                        requestElement = new { localName = "CreateSessionRequest", namespaceUri = TypedNamespace },
                        responseElement = new { localName = "CreateSessionResponse", namespaceUri = TypedNamespace },
                        requestAdapter = new { id = "synthetic-create-session-request", type = "compiled-typed-request" },
                        responseAdapter = new { id = "synthetic-create-session-response", type = "compiled-typed-response" }, sessionLifetimeSeconds = 300,
                        externalAdmission = new { validator = new { id = "synthetic-session-validator", type = "compiled-typed-validator" },
                            endpointBinding = "soap", path = "/service", soapVersion = "1.1", action = "urn:synthetic:ValidateSession",
                            requestElement = new { localName = "ValidateSessionRequest", namespaceUri = TypedNamespace },
                            responseElement = new { localName = "ValidateSessionResponse", namespaceUri = TypedNamespace },
                            intentLifetimeSeconds = 60, timeoutMs = 5_000, maximumRequestBytes = 32_768, maximumResponseBytes = 32_768 } } } }
            };
            string canonical = JsonSerializer.Serialize(definition);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-typed-session", "1.0.0", "1.0", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "publisher", now.AddMinutes(-10), 1, now.AddMinutes(-5), now.AddMinutes(-4));
            ProviderResourceBinding username = Resource("username", 9);
            ProviderResourceBinding password = Resource("password", 9);
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId,
                new Dictionary<string, Uri> { ["soap"] = baseEndpoint }, new Dictionary<string, ProviderResourceBinding> { ["username"] = username, ["password"] = password },
                new Dictionary<string, ProviderResourceBinding>(), 7, "binding-checksum", ConnectorBindingState.Active, now, "publisher");
            snapshot = new(version, bindings, new(versionId, 3, 7, "binding-checksum", "resource-stamp-9"),
                new Dictionary<string, string> { ["username"] = "provider/username", ["password"] = "provider/password" }, new Dictionary<string, string>());
        }

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connectorIdValue, Guid environmentIdValue, PublishedConnectorAccessContext access, CancellationToken cancellationToken) =>
            Task.FromResult<PublishedConnectorSnapshot?>(snapshot);

        internal AuthorizedGatewayInvocation Invocation(SystemGatewayClock clock)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "1.0.0", null);
            return new(new(identity, Guid.NewGuid()), "synthetic-typed-session", "session-bootstrap");
        }

        private ProviderResourceBinding Resource(string id, long revision) => new("synthetic", "Synthetic", "Synthetic", id, ProviderResourceType.Secret, id,
            environmentId, "synthetic-typed-session", "session-bootstrap", "per-run", revision, null, null, "catalog-" + id);
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) =>
            Task.FromResult(logicalReference.Contains("username", StringComparison.Ordinal) ? "synthetic-user" : "synthetic-password");
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class LoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) => string.Equals(host, candidateHost, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class CertificateFixture(X509Certificate2 root, X509Certificate2 server) : IDisposable
    {
        internal X509Certificate2 Root { get; } = root;
        internal X509Certificate2 Server { get; } = server;

        internal static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Synthetic Typed Session Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
            using RSA serverKey = RSA.Create(2048);
            CertificateRequest serverRequest = new("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new();
            san.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 publicServer = serverRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = publicServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(root, server);
        }

        public void Dispose() { Server.Dispose(); Root.Dispose(); }
    }
}
