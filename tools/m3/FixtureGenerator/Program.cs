using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

if (args.Length is < 1 or > 2) throw new InvalidOperationException("Usage: FixtureGenerator <raw-evidence-directory> [gateway-host]");
string rawDirectory = Path.GetFullPath(args[0]);
string gatewayHost = args.Length == 2 ? args[1] : "localhost";
if (string.IsNullOrWhiteSpace(gatewayHost) || gatewayHost.Any(char.IsWhiteSpace)) throw new InvalidOperationException("Gateway host must be a DNS name or IP address without whitespace.");
string certificateDirectory = Path.Combine(rawDirectory, "certificates");
Directory.CreateDirectory(certificateDirectory);

string certificatePassword = Token(32);
string postgresAdminPassword = Token(32);
string postgresRuntimePassword = Token(32);
string activationHmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
string vaultToken = Token(48);
string vendorApiKey = Token(48);
string vendorControlToken = Token(48);
DateTimeOffset now = DateTimeOffset.UtcNow;

using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
CertificateRequest caRequest = new("CN=M3 Synthetic Root " + Guid.NewGuid().ToString("N"), caKey, HashAlgorithmName.SHA256);
caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));
using X509Certificate2 ca = caRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(2));

using X509Certificate2 gateway = CreateIssued("CN=gateway.m3.test", ["gateway.m3.test", "localhost", "127.0.0.1", gatewayHost], false, ca, now);
using X509Certificate2 vault = CreateIssued("CN=vault.m3.test", ["vault.m3.test", "localhost"], false, ca, now);
using X509Certificate2 vendorServer = CreateIssued("CN=vendor.m3.test", ["vendor.m3.test"], false, ca, now);
using X509Certificate2 vendorClient = CreateIssued("CN=M3 Synthetic Vendor Client", [], true, ca, now);
using X509Certificate2 wrongVendorClient = CreateIssued("CN=M3 Wrong Vendor Client", [], true, ca, now);
using X509Certificate2 securityDriver = CreateIssued("CN=M3 Security Driver Installation", [], true, ca, now);
using X509Certificate2 onboardingDriver = CreateIssued("CN=M5 Guided Onboarding Installation", [], true, ca, now);
Guid primaryEnvironmentId = Guid.NewGuid();
Guid securityEnvironmentId = Guid.NewGuid();

await File.WriteAllTextAsync(Path.Combine(certificateDirectory, "ca.crt"), ca.ExportCertificatePem()).ConfigureAwait(false);
await File.WriteAllBytesAsync(Path.Combine(certificateDirectory, "gateway.pfx"), gateway.Export(X509ContentType.Pkcs12, certificatePassword)).ConfigureAwait(false);
await File.WriteAllBytesAsync(Path.Combine(certificateDirectory, "vault.pfx"), vault.Export(X509ContentType.Pkcs12, certificatePassword)).ConfigureAwait(false);
await File.WriteAllBytesAsync(Path.Combine(certificateDirectory, "vendor-server.pfx"), vendorServer.Export(X509ContentType.Pkcs12, certificatePassword)).ConfigureAwait(false);
await File.WriteAllBytesAsync(Path.Combine(certificateDirectory, "security-driver.pfx"), securityDriver.Export(X509ContentType.Pkcs12, certificatePassword)).ConfigureAwait(false);
await File.WriteAllTextAsync(Path.Combine(certificateDirectory, "security-driver.crt"), securityDriver.ExportCertificatePem()).ConfigureAwait(false);
using (ECDsa securityDriverKey = securityDriver.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Synthetic installation key is missing."))
    await File.WriteAllTextAsync(Path.Combine(certificateDirectory, "security-driver.key"), securityDriverKey.ExportPkcs8PrivateKeyPem()).ConfigureAwait(false);
await File.WriteAllTextAsync(Path.Combine(certificateDirectory, "onboarding-driver.crt"), onboardingDriver.ExportCertificatePem()).ConfigureAwait(false);
using (ECDsa onboardingDriverKey = onboardingDriver.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Synthetic onboarding key is missing."))
    await File.WriteAllTextAsync(Path.Combine(certificateDirectory, "onboarding-driver.key"), onboardingDriverKey.ExportPkcs8PrivateKeyPem()).ConfigureAwait(false);

Dictionary<string, string> values = new(StringComparer.Ordinal)
{
    ["M3_RAW_EVIDENCE_DIRECTORY"] = DockerPath(rawDirectory),
    ["M3_CERTIFICATE_DIRECTORY"] = DockerPath(certificateDirectory),
    ["M3_CERTIFICATE_PASSWORD"] = certificatePassword,
    ["M3_POSTGRES_ADMIN_PASSWORD"] = postgresAdminPassword,
    ["M3_POSTGRES_RUNTIME_PASSWORD"] = postgresRuntimePassword,
    ["M3_ACTIVATION_HMAC_BASE64"] = activationHmac,
    ["M3_SYNTHETIC_VAULT_TOKEN"] = vaultToken,
    ["M3_VENDOR_API_KEY"] = vendorApiKey,
    ["M3_VENDOR_CONTROL_TOKEN"] = vendorControlToken,
    ["M3_VENDOR_CLIENT_THUMBPRINT"] = vendorClient.Thumbprint,
    ["M3_VENDOR_CLIENT_PFX_BASE64"] = Convert.ToBase64String(vendorClient.Export(X509ContentType.Pkcs12)),
    ["M3_WRONG_VENDOR_CLIENT_PFX_BASE64"] = Convert.ToBase64String(wrongVendorClient.Export(X509ContentType.Pkcs12)),
    ["M3_PRIMARY_ENVIRONMENT_ID"] = primaryEnvironmentId.ToString("D"),
    ["M3_SECURITY_ENVIRONMENT_ID"] = securityEnvironmentId.ToString("D")
};
string environmentPath = Path.Combine(rawDirectory, "m3a.env");
await File.WriteAllLinesAsync(environmentPath, values.Select(pair => pair.Key + "=" + pair.Value)).ConfigureAwait(false);
await File.WriteAllTextAsync(Path.Combine(rawDirectory, "fixture-public.json"), JsonSerializer.Serialize(new
{
    schemaVersion = 1,
    generatedAtUtc = now,
    expiresAtUtc = now.AddDays(2),
    gatewayHost,
    caSha256 = Convert.ToHexString(SHA256.HashData(ca.RawData)),
    gatewayCertificateSha256 = Convert.ToHexString(SHA256.HashData(gateway.RawData)),
    vaultCertificateSha256 = Convert.ToHexString(SHA256.HashData(vault.RawData)),
    vendorServerCertificateSha256 = Convert.ToHexString(SHA256.HashData(vendorServer.RawData)),
    vendorClientCertificateSha256 = Convert.ToHexString(SHA256.HashData(vendorClient.RawData)),
    vendorClientThumbprint = vendorClient.Thumbprint,
    securityDriverCertificateSha256 = Convert.ToHexString(SHA256.HashData(securityDriver.RawData)),
    onboardingDriverCertificateSha256 = Convert.ToHexString(SHA256.HashData(onboardingDriver.RawData)),
    primaryEnvironmentId
}, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true })).ConfigureAwait(false);
Console.WriteLine(JsonSerializer.Serialize(new { status = "generated", rawDirectory, environmentPath }));

static X509Certificate2 CreateIssued(string subject, string[] names, bool client, X509Certificate2 issuer, DateTimeOffset now)
{
    ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(client ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    OidCollection eku = [new Oid(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1")];
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
    if (names.Length != 0)
    {
        SubjectAlternativeNameBuilder san = new();
        foreach (string name in names.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (System.Net.IPAddress.TryParse(name, out System.Net.IPAddress? address)) san.AddIpAddress(address);
            else san.AddDnsName(name);
        }
        request.CertificateExtensions.Add(san.Build());
    }
    X509Certificate2 publicCertificate = request.Create(issuer, now.AddMinutes(-5), now.AddDays(2), RandomNumberGenerator.GetBytes(16));
    X509Certificate2 result = publicCertificate.CopyWithPrivateKey(key);
    publicCertificate.Dispose();
    key.Dispose();
    return result;
}

static string Token(int bytes) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static string DockerPath(string path) => path.Replace('\\', '/');
