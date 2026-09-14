using System.Security.Cryptography;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Globalization;
using System.Runtime.Loader;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;

if (args is ["--health-probe"])
{
    using HttpClient probe = new() { Timeout = TimeSpan.FromSeconds(3) };
    try
    {
        using HttpResponseMessage response = await probe.GetAsync(Environment.GetEnvironmentVariable("GATEWAY_HEALTH_URL") ?? "http://127.0.0.1:8080/health/live").ConfigureAwait(false);
        Environment.ExitCode = response.IsSuccessStatusCode ? 0 : 1;
    }
    catch (HttpRequestException) { Environment.ExitCode = 1; }
    catch (TaskCanceledException) { Environment.ExitCode = 1; }
    return;
}

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 16 * 1024 * 1024;
    options.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        // Installation credentials are intentionally self-signed. TLS transports the
        // certificate; RuntimeIdentityService owns trust through registry binding, PoP,
        // revocation and signed-request validation.
        https.AllowAnyClientCertificate();
    });
});

GatewayHostOptions hostOptions = builder.Configuration.GetSection("Gateway").Get<GatewayHostOptions>() ?? new();
EndpointResourceCatalog endpointCatalog = new(hostOptions.EndpointResources.Select(value => EndpointResourceCatalogRecord.Create(
    value.EndpointId,
    value.DisplayName,
    value.EnvironmentId,
    value.ConnectorScope,
    value.OperationScope,
    value.LogicalBindingId,
    value.Endpoint,
    value.Revision)));
bool developmentApiKeyCompatibility = string.Equals(hostOptions.Admin.Mode, "DevelopmentApiKey", StringComparison.Ordinal);
bool explicitLoopbackDevelopment = string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal) && (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Testing"));
if (string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal) && !hostOptions.Admin.RequireFourEyes)
    throw new InvalidOperationException("Gateway Admin OIDC requires four-eyes approval.");
if (!hostOptions.Admin.RequireFourEyes && !developmentApiKeyCompatibility && !explicitLoopbackDevelopment)
    throw new InvalidOperationException("Gateway Admin four-eyes approval can be disabled only for an explicit loopback Development mode.");
builder.AddGatewayAdminAuthentication(hostOptions.Admin);
IPAddress? developmentPeer = hostOptions.Admin.DevelopmentPeerAddress is null ? null : IPAddress.Parse(hostOptions.Admin.DevelopmentPeerAddress);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = AdminRateLimiting.CreateGlobalLimiter(hostOptions.Admin.Oidc.CallbackPath);
    options.OnRejected = static (rejection, cancellationToken) =>
        AdminRateLimiting.WriteSafeRejectionAsync(rejection.HttpContext, rejection.Lease, cancellationToken);
});
ForwardedHeadersOptions forwardedHeaders = AdminRateLimiting.CreateForwardedHeadersOptions(hostOptions.Admin.TrustedProxies);
bool usePlatformCertificateForwarding = hostOptions.TrustPlatformClientCertificateForwarding;
if (usePlatformCertificateForwarding)
{
    if (!builder.Environment.IsProduction() || !string.Equals(Environment.GetEnvironmentVariable("GATEWAY_TRUSTED_CERTIFICATE_FORWARDING_BOUNDARY"), "true", StringComparison.Ordinal))
        throw new InvalidOperationException("Platform certificate forwarding requires an explicit trusted Production boundary.");
    builder.Services.AddCertificateForwarding(options => options.CertificateHeader = "X-ARR-ClientCert");
}
builder.Services.AddSingleton(hostOptions);
builder.Services.AddSingleton(endpointCatalog);
builder.Services.AddSingleton<IGatewayClock, SystemGatewayClock>();
builder.Services.AddSingleton<IEnrollmentChallengeStore, InMemoryEnrollmentChallengeStore>();
builder.Services.AddSingleton<IHostResolver, SystemHostResolver>();
builder.Services.AddSingleton<IRestrictedTransport, SystemRestrictedTransport>();
if ((builder.Environment.IsEnvironment("M3Testing") || builder.Environment.IsEnvironment("M4Testing") || builder.Environment.IsEnvironment("M5Testing")) && !string.IsNullOrWhiteSpace(hostOptions.M3PrivateMockHost) && !string.IsNullOrWhiteSpace(hostOptions.M3PrivateMockCidr))
    builder.Services.AddSingleton<IPrivateDestinationAllowance>(new M3PrivateDestinationAllowance(hostOptions.M3PrivateMockHost, hostOptions.M3PrivateMockCidr));
string? connectionString = builder.Configuration.GetConnectionString("GatewayDatabase");
if (string.IsNullOrWhiteSpace(connectionString))
{
    if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing"))
        throw new InvalidOperationException("GatewayDatabase is required outside Development/Testing.");
    builder.Services.AddSingleton<InMemoryGatewayRegistry>();
    builder.Services.AddSingleton<IGatewayRegistry>(services => services.GetRequiredService<InMemoryGatewayRegistry>());
    builder.Services.AddSingleton<IAdminGatewayRegistry>(services => services.GetRequiredService<InMemoryGatewayRegistry>());
    builder.Services.AddSingleton<IAdminDirectoryStore, InMemoryAdminDirectoryStore>();
    builder.Services.AddSingleton<IConnectorConfigurationStore>(services => new InMemoryConnectorConfigurationStore(services.GetRequiredService<IAdminGatewayRegistry>()));
    builder.Services.AddSingleton<IAdminSecurityStore, InMemoryAdminSecurityStore>();
    builder.Services.AddSingleton<IAdminSessionStore, InMemoryAdminSessionStore>();
}
else
{
    builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
    string? adminConnectionString = builder.Configuration.GetConnectionString("GatewayAdminDatabase");
    bool adminPlaneEnabled = string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal) || string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal);
    if (adminPlaneEnabled && string.IsNullOrWhiteSpace(adminConnectionString)) throw new InvalidOperationException("GatewayAdminDatabase is required when the Admin plane and PostgreSQL persistence are enabled.");
    adminConnectionString ??= connectionString;
    builder.Services.AddSingleton(new AdminPostgresDataSource(adminConnectionString));
    builder.Services.AddSingleton<PostgresGatewayRegistry>();
    builder.Services.AddSingleton<IGatewayRegistry>(services => services.GetRequiredService<PostgresGatewayRegistry>());
    builder.Services.AddSingleton<IAdminGatewayRegistry>(services => new PostgresGatewayRegistry(services.GetRequiredService<AdminPostgresDataSource>().Value, services.GetService<IAdminTransactionFaultInjector>()));
    builder.Services.AddSingleton<IAdminDirectoryStore, PostgresAdminDirectoryStore>();
    builder.Services.AddSingleton<IConnectorConfigurationStore, RoutingConnectorConfigurationStore>();
    builder.Services.AddSingleton<IConnectorWorkflowContextStore, PostgresConnectorWorkflowContextStore>();
    builder.Services.AddSingleton<IAdminSecurityStore, PostgresAdminSecurityStore>();
    builder.Services.AddSingleton<IAdminSessionStore, PostgresAdminSessionStore>();
}
builder.Services.AddSingleton<ConnectorDefinitionValidator>();
if (builder.Environment.IsEnvironment("M3Testing") && hostOptions.Operations.Count > 0)
    builder.Services.AddSingleton<IGatewayOperationCatalog>(_ => new GatewayOperationCatalog(hostOptions.Operations.Select(value => value.ToDefinition())));
else
    builder.Services.AddSingleton<IGatewayOperationCatalog>(services => new PublishedConnectorCatalog(
        services.GetRequiredService<IConnectorConfigurationStore>(),
        services.GetRequiredService<ConnectorDefinitionValidator>(),
        services.GetRequiredService<IGatewayClock>(),
        TimeSpan.FromSeconds(hostOptions.ConnectorCacheTtlSeconds is >= 1 and <= 300 ? hostOptions.ConnectorCacheTtlSeconds : throw new InvalidOperationException("Gateway Connector cache TTL must be between 1 and 300 seconds."))));

ProviderServices providerServices = CreateProviderServices(hostOptions.Provider, builder.Environment);
ISecretValueProvider secretProvider = providerServices.SecretValues is CachingSecretValueProvider
    ? providerServices.SecretValues
    : new CachingSecretValueProvider(providerServices.SecretValues, TimeSpan.FromMinutes(5));
builder.Services.AddSingleton(secretProvider);
builder.Services.AddSingleton(providerServices.ClientCertificates);
builder.Services.AddSingleton(providerServices.Health);
builder.Services.AddSingleton(providerServices.CapabilitySource);
if (providerServices.CertificateMetadata is not null) builder.Services.AddSingleton(providerServices.CertificateMetadata);
if (providerServices.CertificatePublicMaterial is not null) builder.Services.AddSingleton(providerServices.CertificatePublicMaterial);
if (providerServices.SigningKeys is not null) builder.Services.AddSingleton(providerServices.SigningKeys);
if (providerServices.Mac is not null) builder.Services.AddSingleton(providerServices.Mac);

builder.Services.AddSingleton<OpaqueSessionLeaseProvider>(services => services.GetRequiredService<SoapSessionClient>().OpaqueSessionLeases);
builder.Services.AddSingleton<IConnectorExecutionStrategy>(services => new OpaqueSessionHttpExecutionStrategy(
    services.GetRequiredService<IConnectorConfigurationStore>(), services.GetRequiredService<OpaqueSessionLeaseProvider>(),
    services.GetRequiredService<IHostResolver>(), services.GetRequiredService<IRestrictedTransport>(), services.GetRequiredService<IGatewayClock>(),
    services.GetService<IPrivateDestinationAllowance>()));
builder.Services.AddSingleton<ComposedSoapExecutionStrategy>(services => new ComposedSoapExecutionStrategy(
    services.GetRequiredService<IConnectorConfigurationStore>(), services.GetRequiredService<ISecretValueProvider>(), services.GetRequiredService<OpaqueSessionLeaseProvider>(),
    services.GetRequiredService<IHostResolver>(), services.GetRequiredService<IRestrictedTransport>(), services.GetRequiredService<IGatewayClock>(),
    services.GetService<IPrivateDestinationAllowance>(), services.GetServices<ITypedComposedSoapRequestAdapter>()));
builder.Services.AddSingleton<IConnectorExecutionStrategy>(services => services.GetRequiredService<ComposedSoapExecutionStrategy>());
builder.Services.AddSingleton<ITypedSessionHandshakeRequestAdapter, SyntheticTypedSessionRequestAdapter>();
builder.Services.AddSingleton<ITypedSessionHandshakeResponseAdapter, SyntheticTypedSessionResponseAdapter>();
builder.Services.AddSingleton<ITypedExternalSessionValidationAdapter, SyntheticExternalSessionValidationAdapter>();
ConnectorExecutionModuleLoader.Register(builder.Services, hostOptions.ExecutionModules);

byte[] activationKey;
string? encodedActivationKey = hostOptions.ActivationHmacKeyBase64;
if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing") && !builder.Environment.IsEnvironment("M3Testing") && !builder.Environment.IsEnvironment("M4Testing") && !builder.Environment.IsEnvironment("M5Testing"))
{
    if (string.IsNullOrWhiteSpace(hostOptions.ActivationHmacSecretReference)) throw new InvalidOperationException("Gateway activation HMAC provider reference is required outside Development/Testing/M3Testing.");
    encodedActivationKey = await secretProvider.GetSecretAsync(hostOptions.ActivationHmacSecretReference, CancellationToken.None).ConfigureAwait(false);
}
try { activationKey = string.IsNullOrWhiteSpace(encodedActivationKey) ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(encodedActivationKey); }
catch (FormatException) { throw new InvalidOperationException("Gateway activation HMAC key is not valid Base64."); }
if (activationKey.Length < 32) throw new InvalidOperationException("Gateway activation HMAC key must contain at least 256 bits.");
builder.Services.AddSingleton(new EnrollmentSecurityOptions { ActivationHmacKey = activationKey });
builder.Services.AddSingleton<GatewayProvisioningService>();
builder.Services.AddSingleton<InstallationEnrollmentService>();
builder.Services.AddSingleton<RuntimeIdentityService>();
builder.Services.AddSingleton<IGatewayInvocationAuthorizer, GatewayInvocationAuthorizer>();
builder.Services.AddSingleton<ISoapSessionResourceStampProvider, PublishedSoapSessionResourceStampProvider>();
builder.Services.AddSingleton(services => new TypedSessionHandshakeAdapterRegistry(
    services.GetServices<ITypedSessionHandshakeRequestAdapter>(),
    services.GetServices<ITypedSessionHandshakeResponseAdapter>(),
    services.GetServices<ITypedExternalSessionValidationAdapter>()));
builder.Services.AddSingleton<PublishedTypedSessionHandshakeResolver>();
builder.Services.AddSingleton(services => new SoapSessionClient(
    services.GetRequiredService<ISecretValueProvider>(),
    services.GetRequiredService<IHostResolver>(),
    services.GetRequiredService<IRestrictedTransport>(),
    services.GetRequiredService<IGatewayClock>(),
    services.GetRequiredService<ISoapSessionResourceStampProvider>(),
    services.GetService<IPrivateDestinationAllowance>()));
builder.Services.AddSingleton<TypedSessionHandshakeRuntime>();
builder.Services.AddSingleton<IAuthorizedVerticalCapabilityRuntime>(services => new AuthorizedVerticalCapabilityRuntime(
    services.GetRequiredService<IConnectorConfigurationStore>(),
    services.GetService<IKeyOperationProvider>(),
    services.GetRequiredService<IClientCertificateProvider>(),
    services.GetService<ICertificateMetadataProvider>(),
    services.GetService<ICertificatePublicMaterialProvider>(),
    services.GetRequiredService<IHostResolver>(),
    services.GetRequiredService<IRestrictedTransport>(),
    services.GetRequiredService<IGatewayClock>(),
    services.GetService<IPrivateDestinationAllowance>()));
builder.Services.AddSingleton(services => new AuthorizedConnectorCapabilityDispatcher(
    services.GetRequiredService<TypedSessionHandshakeRuntime>(),
    services.GetRequiredService<ComposedSoapExecutionStrategy>(),
    services.GetRequiredService<IAuthorizedVerticalCapabilityRuntime>(),
    services.GetService<IConnectorWorkflowContextStore>(),
    services.GetRequiredService<IGatewayClock>()));
builder.Services.AddSingleton<RestrictedEgressService>(services => new RestrictedEgressService(
    services.GetRequiredService<IGatewayRegistry>(),
    services.GetRequiredService<IGatewayOperationCatalog>(),
    services.GetRequiredService<ISecretValueProvider>(),
    services.GetRequiredService<IClientCertificateProvider>(),
    services.GetRequiredService<IHostResolver>(),
    services.GetRequiredService<IRestrictedTransport>(),
    services.GetRequiredService<IGatewayClock>(),
    services.GetService<IPrivateDestinationAllowance>(),
    services.GetServices<IConnectorExecutionStrategy>(),
    services.GetServices<IAuthorizedPublishedOperationExpectationProvider>(),
    services.GetRequiredService<AuthorizedConnectorCapabilityDispatcher>()));
builder.Services.AddSingleton<AdminAccessService>();
builder.Services.AddSingleton<ConnectorApprovalService>();
if (developmentApiKeyCompatibility || !hostOptions.Admin.RequireFourEyes)
    builder.Services.AddSingleton<IConnectorApprovalPolicy, DevelopmentConnectorApprovalPolicy>();
else
    builder.Services.AddSingleton<IConnectorApprovalPolicy, FourEyesConnectorApprovalPolicy>();
builder.Services.AddSingleton<ConnectorAdministrationService>();

WebApplication app = builder.Build();
_ = app.Services.GetRequiredService<RestrictedEgressService>();
if (hostOptions.Provider.Resources.Count > 0)
{
    IConnectorConfigurationStore catalog = app.Services.GetRequiredService<IConnectorConfigurationStore>();
    foreach (GatewayProviderResourceOptions configured in hostOptions.Provider.Resources)
    {
        CertificatePublicMetadata? certificateMetadata = null;
        if (configured.ResourceType == ProviderResourceType.ClientCertificate)
        {
            ICertificateMetadataProvider metadataProvider = providerServices.CertificateMetadata ?? throw new InvalidOperationException("Configured client certificate resources require public metadata capability.");
            ProviderCertificatePublicMetadata metadata = await metadataProvider.GetPublicMetadataAsync(configured.ProviderReference, CancellationToken.None).ConfigureAwait(false);
            string? subjectPublicKeyInfoSha256 = null;
            string? subjectCommonName = null;
            if (providerServices.CertificatePublicMaterial is not null)
            {
                ProviderCertificatePublicMaterial material = await providerServices.CertificatePublicMaterial.GetPublicMaterialAsync(configured.ProviderReference, CancellationToken.None).ConfigureAwait(false);
                if (!SameCertificateMetadata(metadata, material.Metadata))
                    throw new InvalidOperationException("Configured certificate public metadata and material do not identify the same revision.");
                using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(material.LeafCertificateDer.Span);
                if (!string.Equals(metadata.FingerprintSha256, Convert.ToHexString(SHA256.HashData(leaf.RawData)), StringComparison.Ordinal))
                    throw new InvalidOperationException("Configured certificate public metadata does not identify the returned leaf certificate.");
                subjectPublicKeyInfoSha256 = material.SubjectPublicKeyInfoSha256;
                subjectCommonName = CertificateSubjectCommonName(leaf);
            }
            certificateMetadata = new(metadata.FingerprintSha256, metadata.Subject, metadata.Issuer, metadata.NotBefore, metadata.NotAfter, metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version,
                subjectPublicKeyInfoSha256, subjectCommonName);
        }
        await catalog.RegisterProviderResourceAsync(new(Guid.NewGuid(), configured.ProviderId, configured.ProviderDisplayName, configured.ProviderType, configured.ResourceId, configured.ResourceType, configured.DisplayName,
            configured.EnvironmentId, configured.ConnectorScope, configured.OperationScope, configured.ProviderReference, ProviderResourceStatus.Active, configured.Version, 0,
            configured.PublicMetadataRevision, certificateMetadata, string.Empty, DateTimeOffset.UtcNow), CancellationToken.None).ConfigureAwait(false);
    }
}
if (app.Environment.IsEnvironment("Testing"))
    app.Use((context, next) => { context.Connection.RemoteIpAddress ??= IPAddress.Loopback; return next(context); });
if (app.Environment.IsProduction()) app.UseHsts();
if (forwardedHeaders.KnownProxies.Count > 0) app.UseForwardedHeaders(forwardedHeaders);
if (usePlatformCertificateForwarding) app.UseCertificateForwarding();
ILogger gatewayLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SecureIntegration.Gateway.Requests");
app.Use(async (context, next) =>
{
    string requestCorrelationId = Guid.NewGuid().ToString("D");
    context.Response.Headers["X-Correlation-ID"] = requestCorrelationId;
    try
    {
        await next(context).ConfigureAwait(false);
        if (context.Response.StatusCode is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
        {
            string denialCode = context.Response.StatusCode == StatusCodes.Status401Unauthorized ? "BGW-ADMIN-AUTHENTICATION" : "BGW-ADMIN-AUTHORIZATION";
            await AuditAdminDenialAsync(context, denialCode, requestCorrelationId).ConfigureAwait(false);
        }
    }
    catch (GatewayException exception)
    {
        if (context.Response.HasStarted) throw;
        await AuditAdminDenialAsync(context, exception.Code, requestCorrelationId).ConfigureAwait(false);
        context.Response.StatusCode = exception.StatusCode;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, exception.Code, requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Gateway request rejected", status = exception.StatusCode, code = exception.Code, correlationId = requestCorrelationId, retryable = exception.Retryable }).ConfigureAwait(false);
    }
    catch (JsonException)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-PROTOCOL-JSON", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Invalid request", status = 400, code = "BGW-PROTOCOL-JSON", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (BadHttpRequestException exception)
    {
        if (context.Response.HasStarted) throw;
        int status = exception.StatusCode is >= 400 and < 500 ? exception.StatusCode : StatusCodes.Status400BadRequest;
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-PROTOCOL-REQUEST", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Invalid request", status, code = "BGW-PROTOCOL-REQUEST", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (AntiforgeryValidationException)
    {
        if (context.Response.HasStarted) throw;
        await AuditAdminDenialAsync(context, "BGW-ADMIN-CSRF", requestCorrelationId).ConfigureAwait(false);
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-ADMIN-CSRF", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "CSRF validation failed", status = 403, code = "BGW-ADMIN-CSRF", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (ProviderAccessException exception)
    {
        if (context.Response.HasStarted) throw;
        int status = exception.Retryable ? StatusCodes.Status503ServiceUnavailable : StatusCodes.Status500InternalServerError;
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, exception.Code, requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Provider request failed", status, code = exception.Code, correlationId = requestCorrelationId, retryable = exception.Retryable }).ConfigureAwait(false);
    }
    catch (Exception)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestFailed(gatewayLogger, "BGW-INTERNAL", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Gateway request failed", status = 500, code = "BGW-INTERNAL", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
});

app.Use(async (context, next) =>
{
    if (!AdminRateLimiting.IsOidcCallback(context.Request.Path, hostOptions.Admin.Oidc.CallbackPath))
    {
        await next(context).ConfigureAwait(false);
        return;
    }

    Microsoft.AspNetCore.RateLimiting.RateLimiterOptions options =
        context.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>>().Value;
    PartitionedRateLimiter<HttpContext> limiter =
        options.GlobalLimiter ?? throw new InvalidOperationException("Gateway Admin global rate limiter is missing.");
    using RateLimitLease lease = await limiter.AcquireAsync(context, permitCount: 1, context.RequestAborted).ConfigureAwait(false);
    if (!lease.IsAcquired)
    {
        await AdminRateLimiting.WriteSafeRejectionAsync(context, lease, context.RequestAborted).ConfigureAwait(false);
        return;
    }

    context.Items[AdminRateLimiting.PreAuthenticationCallbackLeaseItem] = true;
    await next(context).ConfigureAwait(false);
});
app.UseAuthentication();
app.Use(async (context, next) =>
{
    if (developmentApiKeyCompatibility && context.Request.Path.StartsWithSegments("/admin/v1"))
    {
        try
        {
            context.Items[AdminRateLimiting.DevelopmentApiKeyAuthenticationType] =
                RequireAdmin(context, app.Environment, hostOptions);
            context.User = AdminRateLimiting.DevelopmentApiKeyPrincipal();
        }
        catch (GatewayException failure) when (string.Equals(failure.Code, "BGW-ADMIN-AUTHENTICATION", StringComparison.Ordinal))
        {
            context.Items[AdminRateLimiting.DevelopmentApiKeyRejectedItem] = true;
        }
    }
    await next(context).ConfigureAwait(false);
});
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    string cspNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
    context.Items["AdminCspNonce"] = cspNonce;
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["Content-Security-Policy"] = $"default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'nonce-{cspNonce}'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        if (context.Request.Path.StartsWithSegments("/admin/auth") || context.Request.Path.StartsWithSegments("/admin/api")) context.Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    });
    bool mutation = context.Request.Method is not ("GET" or "HEAD" or "OPTIONS" or "TRACE");
    if (mutation && context.Request.Path.StartsWithSegments("/admin/api"))
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context).ConfigureAwait(false);
    await next(context).ConfigureAwait(false);
});
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = context =>
    {
        context.Context.Response.Headers.CacheControl = context.Context.Request.Path.StartsWithSegments("/admin/assets")
            ? "public,max-age=31536000,immutable"
            : "no-cache";
    }
});
app.UseAuthorization();

app.MapGet("/health/live", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/health/ready", async (IGatewayRegistry registry, IProviderHealthCheck provider, CancellationToken cancellationToken) =>
    await registry.IsReadyAsync(cancellationToken).ConfigureAwait(false) && await provider.IsReadyAsync(cancellationToken).ConfigureAwait(false)
        ? Results.Ok(new { status = "healthy" })
        : Results.Json(new { status = "unhealthy" }, statusCode: 503));

app.MapPost("/v1/enrollments/challenges", async (HttpContext context, InstallationEnrollmentService service, CancellationToken cancellationToken) =>
{
    EnrollmentChallengeRequest request = DeserializeRequired<EnrollmentChallengeRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.CreateChallengeAsync(request, cancellationToken).ConfigureAwait(false));
});
app.MapPost("/v1/enrollments:activate", async (HttpContext context, InstallationEnrollmentService service, CancellationToken cancellationToken) =>
{
    ActivationRequest request = DeserializeRequired<ActivationRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.ActivateAsync(request, cancellationToken).ConfigureAwait(false));
});

app.MapGet("/v1/broker-policy", async (HttpContext context, RuntimeIdentityService identityService, InstallationEnrollmentService enrollmentService, CancellationToken cancellationToken) =>
{
    GatewayClientPrincipal authenticated = await AuthenticateAsync(context, identityService, ReadOnlyMemory<byte>.Empty, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
    return Results.Ok(enrollmentService.GetBrokerPolicy(authenticated.Identity));
});

app.MapPost("/v1/enrollments:renew", async (HttpContext context, RuntimeIdentityService identityService, InstallationEnrollmentService enrollmentService, CancellationToken cancellationToken) =>
{
    byte[] body = await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false);
    RenewalRequest request = DeserializeRequired<RenewalRequest>(body);
    GatewayClientPrincipal authenticated = await AuthenticateAsync(context, identityService, body, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
    return Results.Ok(await enrollmentService.RenewAsync(authenticated.Identity, request, cancellationToken).ConfigureAwait(false));
});

app.MapPost("/v1/connectors/{connectorId}/operations/{operationId}:invoke", async (string connectorId, string operationId, HttpContext context, RuntimeIdentityService identityService, RestrictedEgressService egressService, CancellationToken cancellationToken) =>
{
    _ = RequiredHeader(context, "traceparent");
    byte[] body = await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false);
    GatewayInvokeRequest request = DeserializeRequired<GatewayInvokeRequest>(body);
    GatewayClientPrincipal authenticated = await AuthenticateAsync(context, identityService, body, request.CorrelationId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(await egressService.InvokeAsync(authenticated, connectorId, operationId, request, cancellationToken).ConfigureAwait(false));
});

app.MapPost("/v1/connectors/{connectorId}/operations/{operationId}/session-handshakes/{profileId}:acquire", async (
    string connectorId, string operationId, string profileId, HttpContext context, RuntimeIdentityService identityService,
    TypedSessionHandshakeRuntime runtime, CancellationToken cancellationToken) =>
{
    byte[] body = await ReadBoundedBodyAsync(context.Request, 0, cancellationToken).ConfigureAwait(false);
    GatewayClientPrincipal authenticated = await AuthenticateAsync(context, identityService, body, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(await runtime.AcquireAsync(authenticated, connectorId, operationId, profileId, cancellationToken).ConfigureAwait(false));
});

app.MapPost("/v1/session-admissions/{intentReference}:complete", async (
    string intentReference, HttpContext context, RuntimeIdentityService identityService, TypedSessionHandshakeRuntime runtime,
    CancellationToken cancellationToken) =>
{
    byte[] body = await ReadBoundedBodyAsync(context.Request, 16_384, cancellationToken).ConfigureAwait(false);
    try
    {
        GatewayClientPrincipal authenticated = await AuthenticateAsync(context, identityService, body, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok(await runtime.CompleteExternalAdmissionAsync(authenticated, intentReference, body, cancellationToken).ConfigureAwait(false));
    }
    finally
    {
        CryptographicOperations.ZeroMemory(body);
    }
});

app.MapPost("/admin/v1/connectors:validate", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorImportRequest request = DeserializeRequired<ConnectorImportRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(service.Validate(request.Definition));
});
app.MapPost("/admin/v1/connectors:import", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorImportRequest request = DeserializeRequired<ConnectorImportRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Json(await service.ImportAsync(request.Definition, request.ExpectedChecksumSha256, actor, Correlation(context), cancellationToken).ConfigureAwait(false), statusCode: StatusCodes.Status201Created);
});
app.MapGet("/admin/v1/connectors", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.ListAsync(cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.VersionsAsync(connectorId, cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions/{version}", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.ShowAsync(connectorId, version, cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions/{version}:export", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Text(await service.ExportAsync(connectorId, version, cancellationToken).ConfigureAwait(false), "application/json", Encoding.UTF8);
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:validate", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.ValidateStoredAsync(connectorId, version, request.ExpectedRowVersion, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:publish", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    if (request.ExpectedPublicationRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    return Results.Ok(await service.PublishAsync(connectorId, version, request.ExpectedRowVersion, request.ExpectedPublicationRevision.Value, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}:rollback", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorRollbackRequest request = DeserializeRequired<ConnectorRollbackRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.RollbackAsync(connectorId, request, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:retire", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.RetireAsync(connectorId, version, request.ExpectedRowVersion, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPut("/admin/v1/connectors/{connectorId}/bindings", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorBindingRequest request = DeserializeRequired<ConnectorBindingRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(new { revision = await service.PutBindingsAsync(connectorId, request, actor, Correlation(context), cancellationToken).ConfigureAwait(false) });
});
app.MapPost("/admin/v1/connectors/{connectorId}:test", async (string connectorId, HttpContext context, IGatewayOperationCatalog catalog, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorTestRequest request = DeserializeRequired<ConnectorTestRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, request.OperationId, request.EnvironmentId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "valid", connectorId, operationId = operation.OperationId, connectorVersion = operation.Version });
});

app.MapGet("/admin/auth/login", (HttpContext context) =>
{
    if (string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal))
        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/admin" }, [OpenIdConnectDefaults.AuthenticationScheme]);
    if (string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal))
        return Results.Redirect("/admin/login");
    return Results.NotFound();
});

app.MapGet("/admin/auth/csrf", (HttpContext context, IAntiforgery antiforgery) =>
{
    AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(new { token = tokens.RequestToken });
});

app.MapPost("/admin/auth/development/login", async (DevelopmentLoginRequest request, HttpContext context, IAntiforgery antiforgery, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
    if ((!app.Environment.IsDevelopment() && !app.Environment.IsEnvironment("Testing") && !app.Environment.IsEnvironment("M5Testing")) || !string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal) || !DevelopmentAuthenticationBoundary.IsAllowedPeer(context.Connection.RemoteIpAddress, developmentPeer))
        throw new GatewayException("BGW-ADMIN-DEVELOPMENT-AUTH-DISABLED", 404);
    (string Subject, AdminRole[] Roles) user = request.UserName switch
    {
        "viewer" => ("viewer", [AdminRole.Viewer]),
        "editor" => ("editor", [AdminRole.Viewer, AdminRole.ConnectorEditor]),
        "approver" => ("approver", [AdminRole.Viewer, AdminRole.ConnectorApprover]),
        "operator" => ("operator", [AdminRole.Viewer, AdminRole.Operator]),
        "security-admin" => ("security-admin", [AdminRole.Viewer, AdminRole.SecurityAdministrator]),
        _ => throw new GatewayException("BGW-ADMIN-DEVELOPMENT-USER", 401)
    };
    const string issuer = "https://development.invalid";
    AdminPrincipalRecord principal = await securityStore.EnsurePrincipalAsync(new(issuer, user.Subject, user.Subject, user.Subject + "@example.test"), cancellationToken).ConfigureAwait(false);
    if (user.Roles.Contains(AdminRole.SecurityAdministrator)) _ = await securityStore.TryBootstrapSecurityAdministratorAsync(principal.Id, Guid.NewGuid(), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    foreach (AdminRole role in user.Roles.Where(role => role != AdminRole.SecurityAdministrator))
        _ = await securityStore.AssignRoleAsync(principal.Id, role, null, principal.Id, Guid.NewGuid(), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    ClaimsIdentity identity = new([
        new Claim("iss", issuer, ClaimValueTypes.String, issuer),
        new Claim("sub", user.Subject, ClaimValueTypes.String, issuer),
        new Claim("name", user.Subject, ClaimValueTypes.String, issuer),
        new Claim(ClaimTypes.NameIdentifier, user.Subject, ClaimValueTypes.String, issuer)
    ], CookieAuthenticationDefaults.AuthenticationScheme, "name", ClaimTypes.Role);
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(20) }).ConfigureAwait(false);
    return Results.Ok(new { status = "authenticated" });
});

app.MapPost("/admin/auth/logout", async (HttpContext context, IAntiforgery antiforgery, IAdminSessionStore sessions, IGatewayClock clock) =>
{
    await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
    string? sessionHandle = context.User.FindFirst("sid")?.Value;
    if (!string.IsNullOrWhiteSpace(sessionHandle)) await sessions.RevokeAsync(sessionHandle, clock.UtcNow, context.RequestAborted).ConfigureAwait(false);
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
    if (string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal))
    {
        await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/admin/login" }).ConfigureAwait(false);
        return Results.Empty;
    }
    return Results.Ok(new { status = "signed-out" });
}).RequireAuthorization();

app.MapGet("/admin/auth/me", async (HttpContext context, AdminAccessService access, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(new { id = admin.Principal.Id, displayName = admin.Principal.DisplayName, roles = admin.Assignments.Select(value => new { role = value.Role.ToString(), tenantId = value.TenantId }) });
}).RequireAuthorization();

RouteGroupBuilder adminApi = app.MapGroup("/admin/api/v1").RequireAuthorization();

adminApi.MapGet("/connectors/schema", async (HttpContext context, AdminAccessService access, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    return Results.Content(ConnectorDefinitionArtifacts.SchemaJson, "application/schema+json");
});

adminApi.MapGet("/connectors/sample", async (HttpContext context, AdminAccessService access, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    return Results.Content(ConnectorDefinitionArtifacts.SampleJson, "application/json");
});

adminApi.MapGet("/dashboard", async (HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, IGatewayRegistry registry, IProviderHealthCheck provider, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    AdminPage<TenantRecord> tenants = await directory.ListTenantsAsync(0, 1, cancellationToken).ConfigureAwait(false);
    AdminPage<ApplicationRecord> applications = await directory.ListApplicationsAsync(0, 1, cancellationToken).ConfigureAwait(false);
    bool databaseReady = await registry.IsReadyAsync(cancellationToken).ConfigureAwait(false);
    bool providerReady = await provider.IsReadyAsync(cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { tenants = tenants.Total, applications = applications.Total, database = databaseReady ? "healthy" : "unhealthy", provider = providerReady ? "healthy" : "unhealthy", generatedAtUtc = DateTimeOffset.UtcNow });
});

adminApi.MapGet("/runtime-wire-codes", async (HttpContext context, AdminAccessService access, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    context.Response.Headers.CacheControl = "public, max-age=3600";
    return Results.Ok(RuntimeWireCodeCatalog.Current);
});

adminApi.MapGet("/tenants", async (int? offset, int? limit, string? filter, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListTenantsAsync(offset ?? 0, limit ?? 50, cancellationToken, filter).ConfigureAwait(false));
});

adminApi.MapGet("/tenants/{tenantId:guid}", async (Guid tenantId, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    TenantRecord tenant = await directory.GetTenantAsync(tenantId, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-TENANT-NOT-FOUND", 404);
    context.Response.Headers.ETag = ETag(tenant.RowVersion);
    return Results.Ok(tenant);
});

adminApi.MapPost("/tenants", async (CreateTenantRequest request, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminCode(request.Code, 64); ValidateAdminName(request.DisplayName);
    TenantRecord tenant = new(Guid.NewGuid(), request.Code, request.DisplayName, TenantStatus.Active, DateTimeOffset.UtcNow);
    await registry.AddTenantWithAuditAsync(tenant, AdminAudit(context, admin, tenant.Id, "tenant.create", "tenant", tenant.Id.ToString("D"), "success", "BGW-TENANT-CREATED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(tenant.RowVersion);
    return Results.Created($"/admin/api/v1/tenants/{tenant.Id:D}", tenant);
});

adminApi.MapPut("/tenants/{tenantId:guid}", async (Guid tenantId, UpdateTenantRequest request, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.SecurityAdministrator);
    ValidateAdminName(request.DisplayName);
    TenantRecord result = await registry.UpdateTenantWithAuditAsync(tenantId, request.DisplayName, RequiredIfMatch(context), AdminAudit(context, admin, tenantId, "tenant.update", "tenant", tenantId.ToString("D"), "success", "BGW-TENANT-UPDATED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(result.RowVersion);
    return Results.Ok(result);
});

adminApi.MapPost("/tenants/{tenantId:guid}:disable", async (Guid tenantId, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.SecurityAdministrator);
    TenantRecord result = await registry.DisableTenantWithAuditAsync(tenantId, RequiredIfMatch(context), AdminAudit(context, admin, tenantId, "tenant.disable", "tenant", tenantId.ToString("D"), "success", "BGW-TENANT-DISABLED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(result.RowVersion);
    return Results.Ok(result);
});

adminApi.MapGet("/applications", async (int? offset, int? limit, string? filter, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListApplicationsAsync(offset ?? 0, limit ?? 50, cancellationToken, filter).ConfigureAwait(false));
});

adminApi.MapGet("/applications/{applicationId:guid}", async (Guid applicationId, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    ApplicationRecord application = await directory.GetApplicationAsync(applicationId, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-APPLICATION-NOT-FOUND", 404);
    context.Response.Headers.ETag = ETag(application.RowVersion);
    return Results.Ok(application);
});

adminApi.MapPost("/applications", async (CreateApplicationRequest request, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminCode(request.Code, 100); ValidateAdminName(request.DisplayName);
    if (!Version.TryParse(request.MinimumBrokerVersion, out _) || (request.MaximumBrokerVersion is not null && !Version.TryParse(request.MaximumBrokerVersion, out _))) throw new GatewayException("BGW-ADMIN-BROKER-VERSION", 400);
    ApplicationRecord application = new(Guid.NewGuid(), request.Code, request.DisplayName, ApplicationStatus.Active, request.MinimumBrokerVersion, request.MaximumBrokerVersion, DateTimeOffset.UtcNow);
    await registry.AddApplicationWithAuditAsync(application, AdminAudit(context, admin, null, "application.create", "application", application.Id.ToString("D"), "success", "BGW-APPLICATION-CREATED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(application.RowVersion);
    return Results.Created($"/admin/api/v1/applications/{application.Id:D}", application);
});

adminApi.MapPut("/applications/{applicationId:guid}", async (Guid applicationId, UpdateApplicationRequest request, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminName(request.DisplayName);
    if (!Version.TryParse(request.MinimumBrokerVersion, out _) || (request.MaximumBrokerVersion is not null && !Version.TryParse(request.MaximumBrokerVersion, out _))) throw new GatewayException("BGW-ADMIN-BROKER-VERSION", 400);
    ApplicationRecord result = await registry.UpdateApplicationWithAuditAsync(applicationId, request.DisplayName, request.MinimumBrokerVersion, request.MaximumBrokerVersion, RequiredIfMatch(context), AdminAudit(context, admin, null, "application.update", "application", applicationId.ToString("D"), "success", "BGW-APPLICATION-UPDATED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(result.RowVersion);
    return Results.Ok(result);
});

adminApi.MapPost("/applications/{applicationId:guid}:disable", async (Guid applicationId, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ApplicationRecord result = await registry.DisableApplicationWithAuditAsync(applicationId, RequiredIfMatch(context), AdminAudit(context, admin, null, "application.disable", "application", applicationId.ToString("D"), "success", "BGW-APPLICATION-DISABLED"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(result.RowVersion);
    return Results.Ok(result);
});

adminApi.MapGet("/environments", async (int? offset, int? limit, string? filter, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListEnvironmentsAsync(offset ?? 0, limit ?? 50, cancellationToken, filter).ConfigureAwait(false));
});

adminApi.MapGet("/installations", async (Guid tenantId, int? offset, int? limit, string? filter, Guid? applicationId, Guid? environmentId, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListInstallationsAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken, filter, applicationId, environmentId).ConfigureAwait(false));
});

adminApi.MapGet("/installations/{installationId}", async (Guid installationId, Guid tenantId, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.GetInstallationAsync(tenantId, installationId, cancellationToken).ConfigureAwait(false)
        ?? throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404));
});

adminApi.MapPost("/installations", async (CreateInstallationRequest request, HttpContext context, AdminAccessService access, IAdminGatewayRegistry registry, IGatewayClock clock, EnrollmentSecurityOptions enrollmentOptions, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, request.TenantId, AdminRole.SecurityAdministrator);
    Guid id = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
    GatewayAuditEvent audit = AdminAudit(context, admin, request.TenantId, "installation.create", "installation", id.ToString("D"), "success", "BGW-INSTALLATION-CREATED") with
    {
        Metadata = new Dictionary<string, string> { ["installationKind"] = request.InstallationKind.ToString() }
    };
    GatewayProvisioningService provisioning = new(registry, clock, enrollmentOptions);
    ProvisionedActivation activation = await provisioning.CreateAdminInstallationAsync(new(id, request.TenantId, request.ApplicationId, request.EnvironmentId, InstallationStatus.Pending, null, now, InstallationKind: request.InstallationKind, UpdatedAt: now), admin.ActorId, audit, cancellationToken).ConfigureAwait(false);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Json(activation, statusCode: StatusCodes.Status201Created);
});

adminApi.MapPost("/installations/{installationId}:revoke", async (Guid installationId, Guid tenantId, RevokeInstallationRequest request, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, IAdminGatewayRegistry registry, IEnrollmentChallengeStore challengeStore, IGatewayClock clock, EnrollmentSecurityOptions enrollmentOptions, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.SecurityAdministrator);
    if (await directory.GetInstallationAsync(tenantId, installationId, cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    InstallationEnrollmentService enrollment = new(registry, challengeStore, clock, enrollmentOptions);
    await enrollment.RevokeAdminAsync(installationId, request.Reason, AdminAudit(context, admin, tenantId, "installation.revoke", "installation", installationId.ToString("D"), "success", "BGW-INSTALLATION-REVOKED"), cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "revoked" });
});

adminApi.MapGet("/grants", async (Guid tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListGrantsAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/grants", async (CreateGrantRequest request, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, IAdminGatewayRegistry registry, IConnectorConfigurationStore connectors, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, request.TenantId, AdminRole.SecurityAdministrator);
    if (await directory.GetInstallationAsync(request.TenantId, request.InstallationId, cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    ValidateAdminCode(request.ConnectorId, 100); ValidateAdminCode(request.ConnectorVersion, 64); ValidateAdminCode(request.OperationId, 100);
    ConnectorVersionRecord connectorVersion = await connectors.GetVersionAsync(request.ConnectorId, request.ConnectorVersion, cancellationToken).ConfigureAwait(false)
        ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
    ConnectorGrantAuthority.Validate(connectorVersion, request.ConnectorId, request.OperationId);
    InstallationGrantRecord grant = new(Guid.NewGuid(), request.InstallationId, request.TenantId, request.ConnectorId, request.OperationId, true, DateTimeOffset.UtcNow, request.ValidUntil);
    GrantCreationResult result = await registry.AddGrantWithAuditAsync(grant, connectorVersion, AdminAudit(context, admin, request.TenantId, "grant.create", "installation_grant", grant.Id.ToString("D"), "success", "BGW-GRANT-CREATED"), cancellationToken).ConfigureAwait(false);
    return result.Created
        ? Results.Created($"/admin/api/v1/grants/{result.Grant.Id:D}", result.Grant)
        : Results.Ok(result.Grant);
});

adminApi.MapGet("/audit", async (Guid tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    AdminPage<GatewayAuditEvent> page = await directory.ListAuditAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false);
    bool includeFailureDiagnostics = AdminAccessService.HasRole(admin, tenantId, AdminRole.SecurityAdministrator);
    return Results.Ok(new AdminPage<AdminAuditEventResource>(
        page.Items.Select(value => AuditResource(value, includeFailureDiagnostics)).ToArray(),
        page.Offset,
        page.Limit,
        page.Total));
});

adminApi.MapGet("/audit:export", async (Guid tenantId, DateTimeOffset? fromUtc, DateTimeOffset? toUtc, int? limit, string? cursor, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    DateTimeOffset from = RequireUtcIntervalBoundary(fromUtc);
    DateTimeOffset to = RequireUtcIntervalBoundary(toUtc);
    int pageLimit = limit ?? 100;
    if (from >= to || pageLimit is < 1 or > 1000) throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT", 400);
    AuditExportCursor? parsedCursor = DecodeAuditExportCursor(cursor);
    if (parsedCursor is not null && (parsedCursor.FromUtcTicks != from.UtcDateTime.Ticks || parsedCursor.ToUtcTicks != to.UtcDateTime.Ticks))
        throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT-CURSOR", 400);

    DateTimeOffset? beforeOccurredAt = parsedCursor is null ? null : new DateTimeOffset(parsedCursor.BeforeUtcTicks, TimeSpan.Zero);
    Guid? beforeId = parsedCursor?.BeforeId;
    IReadOnlyList<GatewayAuditEvent> rows = await directory.ExportAuditAsync(tenantId, from, to, beforeOccurredAt, beforeId, pageLimit + 1, cancellationToken).ConfigureAwait(false);
    GatewayAuditEvent[] pageRows = rows.Take(pageLimit).ToArray();
    bool partial = rows.Count > pageLimit;
    bool includeFailureDiagnostics = AdminAccessService.HasRole(admin, tenantId, AdminRole.SecurityAdministrator);
    string? continuation = partial && pageRows.Length > 0
        ? EncodeAuditExportCursor(new(from.UtcDateTime.Ticks, to.UtcDateTime.Ticks, pageRows[^1].OccurredAt.UtcDateTime.Ticks, pageRows[^1].Id))
        : null;
    return Results.Ok(new AdminAuditExportPage<AdminAuditExportEventResource>(
        pageRows.Select(value => AuditExportResource(value, includeFailureDiagnostics)).ToArray(),
        pageLimit,
        from,
        to,
        continuation,
        partial));
});

adminApi.MapPost("/bootstrap", async (HttpContext context, AdminAccessService access, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    string? expected = Environment.GetEnvironmentVariable(hostOptions.Admin.BootstrapTokenEnvironmentVariable, EnvironmentVariableTarget.Process);
    string supplied = context.Request.Headers["X-Bootstrap-Token"].ToString();
    if (!FixedSecretEquals(expected, supplied)) throw new GatewayException("BGW-ADMIN-BOOTSTRAP-DENIED", 403);
    if (!await securityStore.TryBootstrapSecurityAdministratorAsync(admin.Principal.Id, Correlation(context), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false))
        throw new GatewayException("BGW-ADMIN-BOOTSTRAP-COMPLETE", 409);
    return Results.Ok(new { status = "completed" });
});

adminApi.MapPost("/role-assignments", async (AdminRoleAssignmentRequest request, HttpContext context, AdminAccessService access, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    bool exactExistingSelfAssignment = AdminAccessService.RequireRoleAssignment(admin, request.Principal, request.Role, request.TenantId);
    AdminPrincipalRecord target = exactExistingSelfAssignment
        ? admin.Principal
        : await securityStore.EnsurePrincipalAsync(request.Principal, cancellationToken).ConfigureAwait(false);
    AdminRoleAssignmentRecord assignment = await securityStore.AssignRoleAsync(target.Id, request.Role, request.TenantId, admin.Principal.Id, Correlation(context), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    return Results.Ok(assignment);
});

adminApi.MapDelete("/role-assignments/{assignmentId:guid}", async (Guid assignmentId, HttpContext context, AdminAccessService access, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    if (!await securityStore.RevokeRoleAsync(assignmentId, admin.Principal.Id, Correlation(context), DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-ADMIN-ROLE-NOT-FOUND", 404);
    return Results.NoContent();
});

adminApi.MapGet("/connectors", async (int? offset, int? limit, string? filter, HttpContext context, AdminAccessService access, IConnectorConfigurationStore store, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, filter);
    return Results.Ok(await store.ListConnectorsPageAsync(pageOffset, pageLimit, filter, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors:validate", async (ConnectorImportRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    return Results.Ok(service.Validate(request.Definition));
});

adminApi.MapPost("/connectors:import", async (ConnectorImportRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    ConnectorVersionResource created = await service.ImportAsync(request.Definition, request.ExpectedChecksumSha256, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(created.RowVersion);
    return Results.Json(created, statusCode: StatusCodes.Status201Created);
});

adminApi.MapGet("/connectors/{connectorId}/versions", async (string connectorId, int? offset, int? limit, string? filter, HttpContext context, AdminAccessService access, IConnectorConfigurationStore store, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, filter);
    AdminPage<ConnectorVersionRecord> page = await store.ListVersionsPageAsync(connectorId, pageOffset, pageLimit, filter, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new AdminPage<ConnectorVersionResource>(page.Items.Select(ConnectorAdministrationService.Resource).ToArray(), page.Offset, page.Limit, page.Total));
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    ConnectorVersionResource resource = await service.ShowAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}/definition", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Content(await service.ExportAsync(connectorId, version, cancellationToken).ConfigureAwait(false), "application/json");
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:validate", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    long rowVersion = RequiredIfMatch(context);
    ConnectorVersionResource resource = await service.ValidateStoredAsync(connectorId, version, rowVersion, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}/approval-requests", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    ConnectorApprovalRecord result = await approvals.RequestAsync(connectorId, version, admin, Correlation(context), cancellationToken).ConfigureAwait(false);
    return Results.Ok(ApprovalResource(result));
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}/approval-review", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    return Results.Ok(await approvals.ReviewAsync(connectorId, version, admin, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}/approvals", async (string connectorId, string version, ConnectorApprovalAcceptanceRequest request, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    ConnectorApprovalRecord result = await approvals.ApproveAsync(connectorId, version, request, admin, Correlation(context), cancellationToken).ConfigureAwait(false);
    return Results.Ok(ApprovalResource(result));
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}/rejections", async (string connectorId, string version, ConnectorApprovalDecisionRequest request, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    ConnectorApprovalRecord result = await approvals.RejectAsync(connectorId, version, request.Comment, admin, Correlation(context), cancellationToken).ConfigureAwait(false);
    return Results.Ok(ApprovalResource(result));
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}/approvals", async (string connectorId, string version, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminSecurityStore security, IConnectorConfigurationStore connectors, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    ConnectorVersionRecord current = await connectors.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, null);
    AdminPage<ConnectorApprovalRecord> page = await security.ListApprovalsPageAsync(current.Id, pageOffset, pageLimit, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new AdminPage<ConnectorApprovalResource>(page.Items.Select(ApprovalResource).ToArray(), page.Offset, page.Limit, page.Total));
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:publish", async (string connectorId, string version, ConnectorVersionActionRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    long rowVersion = RequiredIfMatch(context);
    if (request.ExpectedPublicationRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    ConnectorVersionResource resource = await service.PublishAsync(connectorId, version, rowVersion, request.ExpectedPublicationRevision.Value, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPost("/connectors/{connectorId}:rollback", async (string connectorId, ConnectorRollbackRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    return Results.Ok(await service.RollbackAsync(connectorId, request, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:retire", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ConnectorVersionResource resource = await service.RetireAsync(connectorId, version, RequiredIfMatch(context), admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPut("/connectors/{connectorId}/bindings", async (string connectorId, ConnectorBindingRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    long? expected = OptionalIfMatch(context);
    if (request.ExpectedRevision is not null && request.ExpectedRevision != expected) throw new GatewayException("BGW-CONCURRENCY-CONFLICT", 409);
    return Results.Ok(new { revision = await service.PutBindingsAsync(connectorId, request with { ExpectedRevision = expected }, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false) });
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}/bindings", async (string connectorId, string version, Guid? environmentId, int? offset, int? limit, HttpContext context, AdminAccessService access, IConnectorConfigurationStore store, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    ConnectorVersionRecord current = await store.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, null);
    AdminPage<ConnectorBindingSet> page = await store.ListBindingsPageAsync(current.Id, pageOffset, pageLimit, environmentId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new AdminPage<ConnectorBindingResource>(page.Items.Select(BindingResource).ToArray(), page.Offset, page.Limit, page.Total));
});

adminApi.MapGet("/provider-resources", async (Guid? environmentId, ProviderResourceType? resourceType, int? offset, int? limit, HttpContext context, AdminAccessService access, IConnectorConfigurationStore store, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, null);
    AdminPage<ProviderResourceCatalogRecord> page = await store.ListProviderResourcesPageAsync(pageOffset, pageLimit, environmentId, resourceType, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new AdminPage<ProviderResourceCatalogResource>(page.Items.Select(ProviderResource).ToArray(), page.Offset, page.Limit, page.Total));
});

adminApi.MapGet("/endpoint-resources", async (Guid environmentId, string connectorId, HttpContext context, AdminAccessService access, EndpointResourceCatalog catalog, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminCode(connectorId, 100);
    IReadOnlyList<EndpointResourceCatalogRecord> resources = catalog.List(environmentId, connectorId);
    return Results.Ok(new AdminPage<EndpointResourceCatalogRecord>(resources, 0, 100, resources.Count));
});

adminApi.MapGet("/provider-resources:resolve", async (Guid environmentId, ProviderResourceType resourceType, string providerId, string resourceId, string? version, long revision, long? publicMetadataRevision, HttpContext context, AdminAccessService access, IConnectorConfigurationStore store, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    ProviderResourceReference reference = new(providerId, resourceId, resourceType, version, publicMetadataRevision);
    ProviderResourceReferenceValidator.Validate(reference);
    IReadOnlyList<ProviderResourceCatalogRecord> matches = await store.FindExactProviderResourcesAsync(environmentId, reference, revision, cancellationToken).ConfigureAwait(false);
    if (matches.Count == 0) throw new GatewayException("BGW-PROVIDER-RESOURCE-NOT-FOUND", 404);
    if (matches.Count != 1) throw new GatewayException("BGW-PROVIDER-RESOURCE-AMBIGUOUS", 409);
    return Results.Ok(ProviderResource(matches[0]));
});

adminApi.MapGet("/role-assignments", async (Guid? principalId, Guid? tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminSecurityStore security, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.SecurityAdministrator);
    (int pageOffset, int pageLimit) = PageArgs(offset, limit, null);
    return Results.Ok(await security.ListAssignmentsAsync(pageOffset, pageLimit, principalId, tenantId, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors/{connectorId}:test", async (string connectorId, ConnectorTestRequest request, HttpContext context, AdminAccessService access, IGatewayOperationCatalog catalog, IAdminGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Operator, AdminRole.SecurityAdministrator);
    GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, request.OperationId, request.EnvironmentId, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, null, "connector.test", "connector", connectorId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "valid", connectorId, operationId = operation.OperationId, connectorVersion = operation.Version });
});

string adminIndexPath = Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "admin", "index.html");
if (File.Exists(adminIndexPath))
{
    app.MapFallback("/admin/{*path:nonfile}", context => ServeAdminIndexAsync(context, adminIndexPath));
}

app.Run();

static bool SameCertificateMetadata(ProviderCertificatePublicMetadata left, ProviderCertificatePublicMetadata right) =>
    string.Equals(left.FingerprintSha256, right.FingerprintSha256, StringComparison.Ordinal) &&
    string.Equals(left.Subject, right.Subject, StringComparison.Ordinal) &&
    string.Equals(left.Issuer, right.Issuer, StringComparison.Ordinal) &&
    left.NotBefore == right.NotBefore && left.NotAfter == right.NotAfter &&
    string.Equals(left.KeyAlgorithm, right.KeyAlgorithm, StringComparison.Ordinal) &&
    left.PublicKeySize == right.PublicKeySize &&
    string.Equals(left.Version, right.Version, StringComparison.Ordinal);

static string? CertificateSubjectCommonName(X509Certificate2 certificate)
{
    const string commonNameObjectIdentifier = "2.5.4.3";
    string? commonName = null;
    foreach (X500RelativeDistinguishedName relativeName in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
    {
        if (relativeName.HasMultipleElements) return null;
        if (!string.Equals(relativeName.GetSingleElementType().Value, commonNameObjectIdentifier, StringComparison.Ordinal)) continue;
        string? value = relativeName.GetSingleElementValue();
        if (commonName is not null || string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
            !value.IsNormalized(NormalizationForm.FormC) || value.Any(char.IsControl))
            return null;
        commonName = value;
    }
    return commonName;
}

static ProviderServices CreateProviderServices(GatewayProviderOptions options, IHostEnvironment environment)
{
    if (string.Equals(options.Kind, "Synthetic", StringComparison.Ordinal))
    {
        if (!environment.IsEnvironment("M3Testing") && !environment.IsEnvironment("M4Testing") && !environment.IsEnvironment("M5Testing") && !environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
            throw new InvalidOperationException("Synthetic provider is not allowed in this environment.");
        if (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Synthetic provider requires an HTTPS endpoint.");
        string? token = Environment.GetEnvironmentVariable(options.AccessTokenEnvironmentVariable, EnvironmentVariableTarget.Process);
        if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("Synthetic provider access token is required.");
        SyntheticProvider provider = new(endpoint, token);
        return new ProviderServices(provider, provider, provider, provider, CertificateMetadata: provider, CertificatePublicMaterial: provider);
    }

    if (string.Equals(options.Kind, "ExternalPack", StringComparison.Ordinal))
    {
        if (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(options.AssemblyPath) || string.IsNullOrWhiteSpace(options.FactoryType))
            throw new InvalidOperationException("External provider pack configuration is incomplete.");
        string assemblyPath = Path.GetFullPath(options.AssemblyPath);
        if (!Path.IsPathFullyQualified(options.AssemblyPath) || !File.Exists(assemblyPath)) throw new InvalidOperationException("External provider pack assembly is unavailable.");
        System.Reflection.Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        Type factoryType = assembly.GetType(options.FactoryType, throwOnError: true, ignoreCase: false) ?? throw new InvalidOperationException("External provider pack factory type was not found.");
        if (!typeof(IProviderPackFactory).IsAssignableFrom(factoryType) || factoryType.IsAbstract || factoryType.GetConstructor(Type.EmptyTypes) is null)
            throw new InvalidOperationException("External provider pack factory does not implement the required contract.");
        IProviderPackFactory factory = (IProviderPackFactory)Activator.CreateInstance(factoryType)!;
        ProviderServices services = factory.Create(new ProviderPackContext(endpoint, options.ClientIdentity, options.Settings));
        if (!services.CapabilitySource.Capabilities.ClientCertificates)
            throw new InvalidOperationException("External provider pack lacks required client-certificate capability.");
        return services;
    }

    if (!string.Equals(options.Kind, "Disabled", StringComparison.Ordinal) && !string.Equals(options.Kind, "InMemory", StringComparison.Ordinal))
        throw new InvalidOperationException("Unknown provider kind.");
    if (!environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
        throw new InvalidOperationException("A configured provider pack is required outside Development/Testing.");
    InMemoryProvider inMemory = new(new Dictionary<string, string>());
    return new ProviderServices(inMemory, inMemory, inMemory, inMemory, SigningKeys: inMemory, CertificateMetadata: inMemory, CertificatePublicMaterial: inMemory);
}

static async Task<GatewayClientPrincipal> AuthenticateAsync(HttpContext context, RuntimeIdentityService service, ReadOnlyMemory<byte> body, Guid correlationId, CancellationToken cancellationToken)
{
    X509Certificate2? certificate = await context.Connection.GetClientCertificateAsync(cancellationToken).ConfigureAwait(false);
    if (certificate is null) throw new GatewayException("BGW-AUTHN-CERTIFICATE-REQUIRED", 401);
    RuntimeSignatureHeaders headers = new(RequiredHeader(context, "X-BG-Timestamp"), RequiredHeader(context, "X-BG-Nonce"), RequiredHeader(context, "X-BG-Content-SHA256"), RequiredHeader(context, "X-BG-Signature"));
    return await service.AuthenticateAsync(certificate, context.Request.Method, context.Request.PathBase + context.Request.Path + context.Request.QueryString, headers, body, correlationId, cancellationToken).ConfigureAwait(false);
}

static string RequiredHeader(HttpContext context, string name)
{
    string value = context.Request.Headers[name].ToString();
    if (string.IsNullOrWhiteSpace(value)) throw new GatewayException("BGW-AUTHN-HEADER-REQUIRED", 401);
    return value;
}

static void ValidateAdminCode(string value, int maximumLength)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')))
        throw new GatewayException("BGW-ADMIN-CODE", 400);
}

static void ValidateAdminName(string value)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > 256 || value.Any(char.IsControl)) throw new GatewayException("BGW-ADMIN-DISPLAY-NAME", 400);
}

static Task AppendAdminAuditAsync(IAdminGatewayRegistry registry, HttpContext context, AdminAccessContext actor, Guid? tenantId, string action, string targetType, string targetId, CancellationToken cancellationToken) =>
    registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, tenantId, "admin", actor.ActorId, action, targetType, targetId, Correlation(context), "success", "BGW-ADMIN-ACTION", new Dictionary<string, string>()), cancellationToken);

static GatewayAuditEvent AdminAudit(HttpContext context, AdminAccessContext actor, Guid? tenantId, string action, string targetType, string targetId, string outcome, string reasonCode) =>
    new(Guid.NewGuid(), DateTimeOffset.UtcNow, tenantId, "administrator", actor.ActorId, action, targetType, targetId, Correlation(context), outcome, reasonCode, new Dictionary<string, string>());

static AdminAuditEventResource AuditResource(GatewayAuditEvent value, bool includeFailureDiagnostics)
{
    SafeFailureDiagnosticsResource? diagnostics = includeFailureDiagnostics && value.FailureDiagnostics is not null
        ? new(
            value.FailureDiagnostics.FailurePhase,
            value.FailureDiagnostics.UpstreamStatus,
            value.FailureDiagnostics.StatusCategory,
            value.FailureDiagnostics.SafeUpstreamCode,
            value.FailureDiagnostics.LocalSafeCode)
        : null;
    return new(value.Id, value.OccurredAt, value.Action, value.TargetType, value.TargetId,
        value.CorrelationId, value.Outcome, value.ReasonCode, diagnostics);
}

static AdminAuditExportEventResource AuditExportResource(GatewayAuditEvent value, bool includeFailureDiagnostics)
{
    SafeFailureDiagnosticsResource? diagnostics = includeFailureDiagnostics && value.FailureDiagnostics is not null
        ? new(
            value.FailureDiagnostics.FailurePhase,
            value.FailureDiagnostics.UpstreamStatus,
            value.FailureDiagnostics.StatusCategory,
            value.FailureDiagnostics.SafeUpstreamCode,
            value.FailureDiagnostics.LocalSafeCode)
        : null;
    return new(value.Id, value.OccurredAt, value.ActorType, value.ActorId, value.Action, value.TargetType, value.TargetId,
        value.CorrelationId, value.Outcome, value.ReasonCode, diagnostics);
}

static ConnectorApprovalResource ApprovalResource(ConnectorApprovalRecord value) =>
    new(value.Id, value.ConnectorVersionId, value.ChecksumSha256, value.BindingDigestSha256, value.RequestedBy, value.ApprovedBy, value.RejectedBy, value.Status.ToString(), value.RequestedAt);

static ConnectorBindingResource BindingResource(ConnectorBindingSet value)
{
    Dictionary<string, string> endpoints = value.Endpoints.ToDictionary(item => item.Key, item => item.Value.AbsoluteUri, StringComparer.Ordinal);
    return new(value.Id, value.ConnectorId, value.ConnectorVersionId, value.EnvironmentId,
        endpoints.ToDictionary(item => item.Key, _ => "[REDACTED]", StringComparer.Ordinal),
        value.SecretResources.ToDictionary(item => item.Key, item => ProviderBinding(item.Value), StringComparer.Ordinal),
        value.CertificateResources.ToDictionary(item => item.Key, item => ProviderBinding(item.Value), StringComparer.Ordinal),
        ConnectorBindingDigests.Component(endpoints), ConnectorBindingDigests.Component(value.SecretResources), ConnectorBindingDigests.Component(value.CertificateResources),
        value.Revision, value.ChecksumSha256, value.State.ToString(), value.UpdatedAt, value.UpdatedBy);
}

static ProviderResourceBindingResource ProviderBinding(ProviderResourceBinding value) => new(value.ProviderId, value.ResourceId, value.ResourceType.ToString(), value.DisplayName, value.Version, value.CatalogRevision, value.PublicMetadataRevision, value.CatalogChecksumSha256);

static ProviderResourceCatalogResource ProviderResource(ProviderResourceCatalogRecord value) => new(value.Id, value.ProviderId, value.ProviderDisplayName, value.ProviderType, value.ResourceId, value.ResourceType.ToString(), value.DisplayName, value.EnvironmentId, value.ConnectorScope, value.OperationScope, value.Status.ToString(), value.Version, value.Revision, value.PublicMetadataRevision, value.CertificateMetadata, value.ChecksumSha256);

static async Task AuditAdminDenialAsync(HttpContext context, string reasonCode, string correlationId)
{
    if (!context.Request.Path.StartsWithSegments("/admin") || context.Items.ContainsKey("AdminDenialAudited")) return;
    context.Items["AdminDenialAudited"] = true;
    string actorId = "anonymous";
    string? handle = context.User.FindFirst("sid")?.Value;
    if (!string.IsNullOrWhiteSpace(handle))
    {
        IAdminSessionStore sessions = context.RequestServices.GetRequiredService<IAdminSessionStore>();
        IGatewayClock clock = context.RequestServices.GetRequiredService<IGatewayClock>();
        AdminSessionRecord? session = await sessions.ValidateAsync(handle, clock.UtcNow, TimeSpan.FromMinutes(20), context.RequestAborted).ConfigureAwait(false);
        if (session is not null) actorId = session.Principal.Id.ToString("D");
    }
    string path = context.Request.Path.Value is { Length: <= 300 } value ? value : "/admin";
    Guid correlation = Guid.TryParse(correlationId, out Guid parsed) ? parsed : Guid.NewGuid();
    await context.RequestServices.GetRequiredService<IAdminGatewayRegistry>().AppendAuditAsync(
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, null, "administrator", actorId, "admin.request.denied", "admin_route", path, correlation, "denied", reasonCode, new Dictionary<string, string> { ["method"] = context.Request.Method }),
        context.RequestAborted).ConfigureAwait(false);
}

static async Task ServeAdminIndexAsync(HttpContext context, string adminIndexPath)
{
    string nonce = context.Items["AdminCspNonce"] as string ?? throw new InvalidOperationException("Admin CSP nonce missing.");
    string index = (await File.ReadAllTextAsync(adminIndexPath, context.RequestAborted).ConfigureAwait(false)).Replace("__CSP_NONCE__", nonce, StringComparison.Ordinal);
    context.Response.ContentType = "text/html; charset=utf-8";
    context.Response.Headers.CacheControl = "no-cache";
    await context.Response.WriteAsync(index, context.RequestAborted).ConfigureAwait(false);
}

static string RequireAdmin(HttpContext context, IHostEnvironment environment, GatewayHostOptions options)
{
    if (context.Items.ContainsKey(AdminRateLimiting.DevelopmentApiKeyRejectedItem))
        throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);

    if (context.User.Identity?.AuthenticationType == AdminRateLimiting.DevelopmentApiKeyAuthenticationType &&
        context.Items.TryGetValue(AdminRateLimiting.DevelopmentApiKeyAuthenticationType, out object? cachedActor) &&
        cachedActor is string actorFromAuthenticatedRequest)
        return actorFromAuthenticatedRequest;

    if (!string.Equals(options.Admin.Mode, "DevelopmentApiKey", StringComparison.Ordinal) || (!environment.IsDevelopment() && !environment.IsEnvironment("Testing") && !environment.IsEnvironment("M4Testing")))
        throw new GatewayException("BGW-ADMIN-AUTHENTICATION-DISABLED", 404);
    string? expected = Environment.GetEnvironmentVariable(options.Admin.ApiKeyEnvironmentVariable, EnvironmentVariableTarget.Process);
    string supplied = context.Request.Headers["X-Admin-Key"].ToString();
    if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(supplied)) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    bool valid = expectedBytes.Length == suppliedBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
    CryptographicOperations.ZeroMemory(expectedBytes);
    CryptographicOperations.ZeroMemory(suppliedBytes);
    if (!valid) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
    string actor = context.Request.Headers["X-Admin-Actor"].ToString();
    return actor.Length is >= 3 and <= 100 && actor.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '@') ? actor : "development-admin";
}

static Guid Correlation(HttpContext context) => Guid.TryParse(context.Response.Headers["X-Correlation-ID"], out Guid value) ? value : Guid.NewGuid();


static bool FixedSecretEquals(string? expected, string supplied)
{
    if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(supplied)) return false;
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    try { return expectedBytes.Length == suppliedBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes); }
    finally { CryptographicOperations.ZeroMemory(expectedBytes); CryptographicOperations.ZeroMemory(suppliedBytes); }
}

static string ETag(long rowVersion) => FormattableString.Invariant($"\"{rowVersion}\"");

static long RequiredIfMatch(HttpContext context)
{
    if (!context.Request.Headers.ContainsKey("If-Match")) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    string value = context.Request.Headers.IfMatch.ToString();
    if (value.Length < 3 || value[0] != '"' || value[^1] != '"' || !long.TryParse(value.AsSpan(1, value.Length - 2), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long rowVersion) || rowVersion < 1)
        throw new GatewayException("BGW-CONCURRENCY-ETAG", 400);
    return rowVersion;
}

static long? OptionalIfMatch(HttpContext context)
{
    if (!context.Request.Headers.ContainsKey("If-Match")) return null;
    return RequiredIfMatch(context);
}

static (int Offset, int Limit) PageArgs(int? offset, int? limit, string? filter)
{
    int resolvedOffset = offset ?? 0; int resolvedLimit = limit ?? 50;
    if (resolvedOffset < 0 || resolvedLimit is < 1 or > 100 || filter?.Length > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400);
    return (resolvedOffset, resolvedLimit);
}

static DateTimeOffset RequireUtcIntervalBoundary(DateTimeOffset? value)
{
    if (value is null || value.Value.Offset != TimeSpan.Zero) throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT", 400);
    return value.Value;
}

static string EncodeAuditExportCursor(AuditExportCursor cursor)
{
    string value = FormattableString.Invariant($"{cursor.FromUtcTicks}|{cursor.ToUtcTicks}|{cursor.BeforeUtcTicks}|{cursor.BeforeId:D}");
    return Convert.ToBase64String(Encoding.ASCII.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

static AuditExportCursor? DecodeAuditExportCursor(string? value)
{
    if (string.IsNullOrWhiteSpace(value)) return null;
    if (value.Length > 256) throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT-CURSOR", 400);
    try
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        string decoded = Encoding.ASCII.GetString(Convert.FromBase64String(padded));
        string[] parts = decoded.Split('|');
        if (parts.Length != 4 ||
            !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long fromTicks) ||
            !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out long toTicks) ||
            !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out long beforeTicks) ||
            !Guid.TryParseExact(parts[3], "D", out Guid beforeId))
            throw new FormatException();
        _ = new DateTimeOffset(fromTicks, TimeSpan.Zero);
        _ = new DateTimeOffset(toTicks, TimeSpan.Zero);
        _ = new DateTimeOffset(beforeTicks, TimeSpan.Zero);
        return new(fromTicks, toTicks, beforeTicks, beforeId);
    }
    catch (Exception exception) when (exception is FormatException or ArgumentOutOfRangeException)
    {
        throw new GatewayException("BGW-ADMIN-AUDIT-EXPORT-CURSOR", 400);
    }
}

static async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    => await ReadBoundedBodyAsync(request, 16 * 1024 * 1024, cancellationToken).ConfigureAwait(false);

static async Task<byte[]> ReadBoundedBodyAsync(HttpRequest request, long maximumBytes, CancellationToken cancellationToken)
{
    if (maximumBytes < 0 || request.ContentLength > maximumBytes) throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 413);
    using MemoryStream output = new();
    await request.Body.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    if (output.Length > maximumBytes) throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 413);
    return output.ToArray();
}

static T DeserializeRequired<T>(byte[] body) => JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }) ?? throw new GatewayException("BGW-PROTOCOL-JSON", 400);

/// <summary>Gateway API entry point exposed for in-process integration tests.</summary>
public partial class Program;

internal sealed record AuditExportCursor(long FromUtcTicks, long ToUtcTicks, long BeforeUtcTicks, Guid BeforeId);
