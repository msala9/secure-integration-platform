using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using SecureIntegration.Samples.LocalBroker;
using SecureIntegration.TestDiagnostics;
using Xunit;

namespace SecureIntegration.Broker.Integration.Tests;

public sealed class WindowsBrokerIntegrationTests
{
    [Fact]
    public async Task Credential_sample_configures_reloads_and_replaces_only_ciphertext()
    {
        using TestDirectory temporary = new();
        string path = Path.Combine(temporary.Path, "application", "credential.envelope");
        byte[] first = Encoding.UTF8.GetBytes(RandomNumberGenerator.GetHexString(64));
        byte[] second = Encoding.UTF8.GetBytes(RandomNumberGenerator.GetHexString(64));
        try
        {
            await WithBrokerAsync(async client =>
            {
                await CredentialExample.ConfigureAsync(client, path, first, TestContext.Current.CancellationToken);
                byte[] envelope = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                Assert.False(envelope.AsSpan().IndexOf(first) >= 0);
                byte[] recovered = await CredentialExample.ReadAsync(client, path, TestContext.Current.CancellationToken);
                try { Assert.True(recovered.AsSpan().SequenceEqual(first)); }
                finally { CryptographicOperations.ZeroMemory(recovered); }
                await CredentialExample.ConfigureAsync(client, path, second, TestContext.Current.CancellationToken);
                recovered = await CredentialExample.ReadAsync(client, path, TestContext.Current.CancellationToken);
                try { Assert.True(recovered.AsSpan().SequenceEqual(second)); }
                finally { CryptographicOperations.ZeroMemory(recovered); }
                Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
            });
        }
        finally { CryptographicOperations.ZeroMemory(first); CryptographicOperations.ZeroMemory(second); }
    }

    [Fact]
    public async Task Credential_sample_failed_replacement_preserves_previous_configuration()
    {
        using TestDirectory temporary = new();
        string path = Path.Combine(temporary.Path, "application", "credential.envelope");
        byte[] first = Encoding.UTF8.GetBytes(RandomNumberGenerator.GetHexString(64));
        byte[] second = Encoding.UTF8.GetBytes(RandomNumberGenerator.GetHexString(64));
        try
        {
            await WithBrokerAsync(async client =>
            {
                await CredentialExample.ConfigureAsync(client, path, first, TestContext.Current.CancellationToken);
                byte[] before = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                // A real pre-commit filesystem failure, not a production fault-injection hook.
                using (FileStream locked = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    await Assert.ThrowsAsync<IOException>(() => CredentialExample.ConfigureAsync(client, path, second, TestContext.Current.CancellationToken));
                byte[] after = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                Assert.True(before.AsSpan().SequenceEqual(after));
                byte[] recovered = await CredentialExample.ReadAsync(client, path, TestContext.Current.CancellationToken);
                try { Assert.True(recovered.AsSpan().SequenceEqual(first)); }
                finally { CryptographicOperations.ZeroMemory(recovered); }
                Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
            });
        }
        finally { CryptographicOperations.ZeroMemory(first); CryptographicOperations.ZeroMemory(second); }
    }

    [Fact]
    public async Task Credential_sample_refuses_foreign_context_tamper_and_broad_file_ownership()
    {
        using TestDirectory temporary = new();
        string path = Path.Combine(temporary.Path, "application", "credential.envelope");
        byte[] input = Encoding.UTF8.GetBytes(RandomNumberGenerator.GetHexString(64));
        try
        {
            await WithBrokerAsync(async client =>
            {
                await CredentialExample.ConfigureAsync(client, path, input, TestContext.Current.CancellationToken);
                byte[] original = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                ProtectedDataResult other = await client.ProtectDataAsync(new ProtectDataRequest
                {
                    Purpose = "test", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String(input)
                }, TestContext.Current.CancellationToken);
                byte[] foreign = Convert.FromBase64String(other.EnvelopeBase64);
                await File.WriteAllBytesAsync(path, foreign, TestContext.Current.CancellationToken);
                BrokerClientException denied = await Assert.ThrowsAsync<BrokerClientException>(() =>
                    CredentialExample.ConfigureAsync(client, path, input, TestContext.Current.CancellationToken));
                Assert.Equal("authentication_failed", denied.Code);
                byte[] after = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                Assert.True(foreign.AsSpan().SequenceEqual(after));
                foreign = original;
                foreign[^1] ^= 1;
                await File.WriteAllBytesAsync(path, foreign, TestContext.Current.CancellationToken);
                denied = await Assert.ThrowsAsync<BrokerClientException>(() => CredentialExample.ReadAsync(client, path, TestContext.Current.CancellationToken));
                Assert.Equal("authentication_failed", denied.Code);
                FileSecurity security = new FileInfo(path).GetAccessControl();
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.Read, AccessControlType.Allow));
                new FileInfo(path).SetAccessControl(security);
                InvalidOperationException ownership = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    CredentialExample.ConfigureAsync(client, path, input, TestContext.Current.CancellationToken));
                Assert.Equal("CREDENTIAL_OWNERSHIP_DENIED", ownership.Message);
                after = await File.ReadAllBytesAsync(path, TestContext.Current.CancellationToken);
                Assert.True(foreign.AsSpan().SequenceEqual(after));
                Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
            });
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    [Fact]
    public void Credential_sample_runtime_input_is_bounded_and_roundtrips()
    {
        string value = RandomNumberGenerator.GetHexString(64);
        using StringReader reader = new(value + "\r\n");
        byte[] input = CredentialExample.ReadInput(reader);
        try { Assert.True(Encoding.UTF8.GetString(input).AsSpan().SequenceEqual(value)); }
        finally { CryptographicOperations.ZeroMemory(input); }
        foreach (string invalid in new[] { "", "\n", "\0", new string('a', CredentialExample.MaximumCharacters + 1) })
        {
            using StringReader invalidReader = new(invalid);
            InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() => CredentialExample.ReadInput(invalidReader));
            Assert.Equal("CREDENTIAL_INPUT_INVALID", failure.Message);
        }
    }

    [Fact]
    public async Task M3_security_driver_UserKeySet_client_certificate_is_Schannel_compatible()
    {
        const string password = "synthetic-test-password";
        using ECDsa serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest serverRequest = new("CN=localhost", serverKey, HashAlgorithmName.SHA256);
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName("localhost");
        names.AddIpAddress(IPAddress.Loopback);
        serverRequest.CertificateExtensions.Add(names.Build());
        using X509Certificate2 sourceServerCertificate = serverRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));

        using ECDsa clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest clientRequest = new("CN=M3 Schannel probe", clientKey, HashAlgorithmName.SHA256);
        clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        using X509Certificate2 sourceClientCertificate = clientRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));

        string serverPfxPath = Path.Combine(Path.GetTempPath(), $"m3-schannel-server-{Guid.NewGuid():N}.pfx");
        string clientPfxPath = Path.Combine(Path.GetTempPath(), $"m3-schannel-client-{Guid.NewGuid():N}.pfx");
        await File.WriteAllBytesAsync(serverPfxPath, sourceServerCertificate.Export(X509ContentType.Pkcs12, password), TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(clientPfxPath, sourceClientCertificate.Export(X509ContentType.Pkcs12, password), TestContext.Current.CancellationToken);
        try
        {
            using X509Certificate2 serverCertificate = X509CertificateLoader.LoadPkcs12FromFile(serverPfxPath, password, X509KeyStorageFlags.UserKeySet);
            using X509Certificate2 clientCertificate = X509CertificateLoader.LoadPkcs12FromFile(clientPfxPath, password, X509KeyStorageFlags.UserKeySet);
            using TcpListener listener = new(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            Task server = Task.Run(async () =>
            {
                using TcpClient accepted = await listener.AcceptTcpClientAsync(TestContext.Current.CancellationToken);
                await using SslStream tls = new(accepted.GetStream(), false, (_, certificate, _, _) =>
                    string.Equals(certificate?.GetCertHashString(HashAlgorithmName.SHA256), clientCertificate.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase));
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, TestContext.Current.CancellationToken);
                int marker = tls.ReadByte();
                Assert.Equal(42, marker);
            }, TestContext.Current.CancellationToken);

            using TcpClient client = new();
            await client.ConnectAsync(IPAddress.Loopback, port, TestContext.Current.CancellationToken);
            await using SslStream clientTls = new(client.GetStream(), false, (_, certificate, _, _) =>
                string.Equals(certificate?.GetCertHashString(HashAlgorithmName.SHA256), serverCertificate.GetCertHashString(HashAlgorithmName.SHA256), StringComparison.OrdinalIgnoreCase));
            try
            {
                await clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    ClientCertificates = new X509CertificateCollection { clientCertificate },
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, TestContext.Current.CancellationToken);
            }
            catch (Exception clientException)
            {
                try { await server; }
                catch (Exception serverException) { throw new AggregateException(clientException, serverException); }
                throw;
            }
            clientTls.WriteByte(42);
            await clientTls.FlushAsync(TestContext.Current.CancellationToken);
            await server;
        }
        finally
        {
            File.Delete(serverPfxPath);
            File.Delete(clientPfxPath);
        }
    }

    [Fact]
    public void M3_IT_BRK_Installation_credential_uses_nonexportable_CNG_P256_key()
    {
        using TestDirectory temporary = new();
        string keyName = "SecureIntegration.M3.Tests." + Guid.NewGuid().ToString("N");
        GatewayInstallationOptions options = new()
        {
            Enabled = true,
            BaseAddress = "https://gateway.example.test/",
            ActivationCodeId = Guid.NewGuid().ToString("D"),
            CngKeyName = keyName,
            BrokerVersion = "1.0.0"
        };
        string? thumbprint = null;
        try
        {
            using ProductionGatewayInvoker invoker = new(options, temporary.Path);
            using X509Certificate2 certificate = invoker.LoadOrCreateCertificate();
            thumbprint = certificate.Thumbprint;
            Assert.True(certificate.HasPrivateKey);
            using ECDsaCng key = Assert.IsType<ECDsaCng>(certificate.GetECDsaPrivateKey());
            Assert.Equal(256, key.KeySize);
            Assert.Equal(CngExportPolicies.None, key.Key.ExportPolicy);
            Assert.ThrowsAny<CryptographicException>(() => key.ExportPkcs8PrivateKey());
        }
        finally
        {
            if (thumbprint is not null)
            {
                using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                foreach (X509Certificate2 certificate in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)) store.Remove(certificate);
            }
            if (CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                using CngKey key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
                key.Delete();
            }
        }
    }

    [Fact]
    public async Task Named_pipe_caller_identity_is_captured_from_the_kernel()
    {
        string name = "SecureIntegration.Identity.Tests." + Guid.NewGuid().ToString("N");
        await using NamedPipeServerStream server = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using NamedPipeClientStream client = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        Task accepting = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        await client.ConnectAsync(TestContext.Current.CancellationToken);
        await accepting;
        ValueTask writing = client.WriteAsync(new byte[] { 1 }, TestContext.Current.CancellationToken);
        byte[] marker = new byte[1];
        await server.ReadExactlyAsync(marker, TestContext.Current.CancellationToken);
        await writing;
        using CallerIdentity caller = NamedPipeCallerIdentity.Capture(server);
        Assert.Equal((uint)Environment.ProcessId, caller.ProcessId);
        Assert.Equal(Environment.ProcessPath, caller.ExecutablePath, ignoreCase: true);
        Assert.Equal(Process.GetCurrentProcess().StartTime.ToUniversalTime(), caller.ProcessStartTimeUtc.UtcDateTime, TimeSpan.FromSeconds(1));
        Microsoft.Win32.SafeHandles.SafeProcessHandle retainedHandle = Assert.IsType<Microsoft.Win32.SafeHandles.SafeProcessHandle>(typeof(CallerIdentity).GetField("processHandle", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(caller));
        FileStream retainedExecutable = Assert.IsType<FileStream>(typeof(CallerIdentity).GetField("executableFile", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(caller));
        Microsoft.Win32.SafeHandles.SafeFileHandle retainedFileHandle = retainedExecutable.SafeFileHandle;
        caller.Dispose();
        Assert.True(retainedHandle.IsClosed);
        Assert.True(retainedFileHandle.IsClosed);
    }

    [Fact]
    public void DPAPI_CurrentUser_round_trip_and_ciphertext_is_not_plaintext()
    {
        WindowsDpapiProtectionProvider provider = new();
        byte[] plaintext = "offline-secret-marker"u8.ToArray();
        byte[] protectedValue = provider.Protect(plaintext, "test-entropy"u8.ToArray());
        Assert.False(protectedValue.AsSpan().IndexOf(plaintext) >= 0);
        Assert.Equal(plaintext, provider.Unprotect(protectedValue, "test-entropy"u8.ToArray()));
    }

    [Fact]
    public void Broker_storage_ACL_is_protected_and_has_no_world_grant()
    {
        using TestDirectory temporary = new();
        WindowsStorageSecurity.HardenDirectory(temporary.Path);
        DirectorySecurity security = new DirectoryInfo(temporary.Path).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        SecurityIdentifier world = new(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule => rule.IdentityReference == world && rule.AccessControlType == AccessControlType.Allow);
    }

    [Fact]
    public void Named_pipe_ACL_is_protected_and_contains_only_configured_principals()
    {
        using TestDirectory temporary = new();
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        BrokerOptions options = new()
        {
            PipeName = "SecureIntegration.Acl.Tests." + Guid.NewGuid().ToString("N"),
            InstallationId = "acl-test",
            DataDirectory = temporary.Path,
            Applications = [new ApplicationPolicy { RegistrationId = "app", AllowedUserSids = [sid], ExecutablePaths = [Environment.ProcessPath!] }],
        };
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        BrokerApplicationService application = new(secrets, protection, new AeadDataProtector(keys, options.InstallationId), options.InstallationId);
        NamedPipeBrokerServer broker = new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(application), new NullAudit());
        using NamedPipeServerStream pipe = Assert.IsType<NamedPipeServerStream>(typeof(NamedPipeBrokerServer).GetMethod("CreatePipe", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(broker, null));
        PipeSecurity security = pipe.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        string[] allowed = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().Where(static rule => rule.AccessControlType == AccessControlType.Allow).Select(static rule => rule.IdentityReference.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        Assert.All(allowed, value => Assert.Equal(sid, value, ignoreCase: true));
    }

    [Fact]
    public async Task Service_install_contract_uses_a_virtual_service_account()
    {
        string root = FindRepositoryRoot();
        string script = await File.ReadAllTextAsync(System.IO.Path.Combine(root, "deploy", "windows", "install-service.ps1"), TestContext.Current.CancellationToken);
        Assert.Contains("NT SERVICE\\SecureIntegrationBroker", script, StringComparison.Ordinal);
        Assert.DoesNotContain("LocalSystem", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Offline_storage_contains_no_plaintext_and_corruption_is_denied()
    {
        using TestDirectory temporary = new();
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        BrokerApplicationService service = new(secrets, protection, new AeadDataProtector(keys, "installation-a"), "installation-a");
        string reference = await service.PutLocalSecretAsync("app-a", "tenant-key", "Tenant", ["ComputeHmac"], "plaintext-never-at-rest"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken);
        string persisted = await File.ReadAllTextAsync(Directory.GetFiles(System.IO.Path.Combine(temporary.Path, "secrets"))[0], TestContext.Current.CancellationToken);
        Assert.DoesNotContain("plaintext-never-at-rest", persisted, StringComparison.Ordinal);

        string keyPath = System.IO.Path.Combine(temporary.Path, "keys", "key-1.bin");
        await keys.InitializeAsync(TestContext.Current.CancellationToken);
        _ = await keys.GetActiveAsync(TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(keyPath, [1, 2, 3], TestContext.Current.CancellationToken);
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => keys.GetAsync(1, TestContext.Current.CancellationToken));
        Assert.Equal("data_key_unwrap_failed", failure.Code);
        Assert.StartsWith("lsr_", reference, StringComparison.Ordinal);

        const string corruptReference = "lsr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string corruptPath = System.IO.Path.Combine(temporary.Path, "secrets", corruptReference + ".json");
        await File.WriteAllTextAsync(corruptPath, "{\"SecretRef\":\"lsr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"OwnerApplicationId\":\"app-a\",\"LogicalName\":\"x\",\"SecretClass\":\"Tenant\",\"AllowedOperations\":[],\"ProtectedValueBase64\":\"not-base64\"}", TestContext.Current.CancellationToken);
        BrokerException corruptSecret = await Assert.ThrowsAsync<BrokerException>(() => secrets.FindAsync(corruptReference, TestContext.Current.CancellationToken));
        Assert.Equal("local_storage_corrupt", corruptSecret.Code);
    }

    [Fact]
    public async Task AC005_Installation_key_and_ciphertext_differentiation()
    {
        using TestDirectory firstDirectory = new();
        using TestDirectory secondDirectory = new();
        WindowsDpapiProtectionProvider protection = new();
        using FileDataKeyRepository firstKeys = new(firstDirectory.Path, protection);
        using FileDataKeyRepository secondKeys = new(secondDirectory.Path, protection);
        await firstKeys.InitializeAsync(TestContext.Current.CancellationToken);
        await secondKeys.InitializeAsync(TestContext.Current.CancellationToken);
        byte[] first = await new AeadDataProtector(firstKeys, "installation-a").ProtectAsync("app", "purpose", "text/plain", [1], TestContext.Current.CancellationToken);
        byte[] second = await new AeadDataProtector(secondKeys, "installation-b").ProtectAsync("app", "purpose", "text/plain", [1], TestContext.Current.CancellationToken);
        Assert.NotEqual((await firstKeys.GetActiveAsync(TestContext.Current.CancellationToken)).Value, (await secondKeys.GetActiveAsync(TestContext.Current.CancellationToken)).Value);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity()
    {
        using TestDirectory temporary = new();
        WindowsDpapiProtectionProvider protection = new();
        string secretReference;
        byte[] envelope;
        byte[] expectedHmac = HMACSHA256.HashData("restart-key"u8.ToArray(), "message"u8.ToArray());
        using (FileLocalSecretRepository secrets = new(temporary.Path))
        using (FileDataKeyRepository keys = new(temporary.Path, protection))
        {
            await keys.InitializeAsync(TestContext.Current.CancellationToken);
        BrokerApplicationService beforeRestart = new(secrets, protection, new AeadDataProtector(keys, "installation-restart"), "installation-restart");
            secretReference = await beforeRestart.PutLocalSecretAsync("app-a", "restart-key", "Tenant", ["ComputeHmac"], "restart-key"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken);
            envelope = await beforeRestart.ProtectDataAsync("app-a", "restart", "application/json", "persisted-data"u8.ToArray(), TestContext.Current.CancellationToken);
        }

        using (FileLocalSecretRepository secrets = new(temporary.Path))
        using (FileDataKeyRepository keys = new(temporary.Path, protection))
        {
        BrokerApplicationService afterRestart = new(secrets, protection, new AeadDataProtector(keys, "installation-restart"), "installation-restart");
            Assert.Equal(expectedHmac, await afterRestart.ComputeHmacAsync("app-a", secretReference, "message"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken));
            Assert.Equal("persisted-data"u8.ToArray(), await afterRestart.UnprotectDataAsync("app-a", "restart", "application/json", envelope, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied()
    {
        await WithBrokerAsync(async client =>
        {
            Assert.False((await client.GetStatusAsync(TestContext.Current.CancellationToken)).GatewayConfigured);
            ProtectedDataResult protectedData = await client.ProtectDataAsync(new ProtectDataRequest { Purpose = "test", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String("hello"u8) }, TestContext.Current.CancellationToken);
            UnprotectedDataResult plaintext = await client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = "test", ContentType = "text/plain", EnvelopeBase64 = protectedData.EnvelopeBase64 }, TestContext.Current.CancellationToken);
            Assert.Equal("hello"u8.ToArray(), Convert.FromBase64String(plaintext.PlaintextBase64));
        });

        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidHash: true));
        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidPublisher: true));
    }

    [Fact]
    public async Task Pipe_supports_concurrent_clients_and_deadline_cancellation()
    {
        CapturingAudit deadlineAudit = new();
        await WithBrokerAsync(async client =>
        {
            Task<ProtectedDataResult>[] requests = Enumerable.Range(0, 8).Select(index => client.ProtectDataAsync(new ProtectDataRequest { Purpose = "concurrent-" + index, PlaintextBase64 = Convert.ToBase64String([checked((byte)index)]) }, TestContext.Current.CancellationToken)).ToArray();
            ProtectedDataResult[] results = await Task.WhenAll(requests);
            Assert.Equal(8, results.Length);
        });

        await WithBrokerAsync(async client =>
        {
            BrokerClientException failure = await Assert.ThrowsAsync<BrokerClientException>(() => client.InvokeGatewayAsync(new InvokeGatewayRequest { ConnectorId = "secure-layer-demo", OperationId = "submit", PayloadBase64 = "e30=" }, TestContext.Current.CancellationToken));
            Assert.Equal("deadline_exceeded", failure.Code);
        }, operationTimeout: TimeSpan.FromMilliseconds(100), gateway: new SlowGateway(), audit: deadlineAudit);
        Assert.Equal("deadline_exceeded", Assert.Single(deadlineAudit.Outcomes).ErrorCode);
    }

    [Fact]
    public async Task Incomplete_handshake_releases_connection_and_allows_later_request()
    {
        using TimeoutObservation observation = new("broker");
        CapturingAudit audit = new() { ConnectionObserved = () => observation.Mark("connection-audit") };
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            observation.Mark("client-connect-start");
            await using NamedPipeClientStream stalled = await ConnectRawPipeAsync(name, TestContext.Current.CancellationToken);
            observation.Mark("client-connected-not-proof-of-server-admission");
            await stalled.WriteAsync("B"u8.ToArray(), TestContext.Current.CancellationToken).ConfigureAwait(false);
            await stalled.FlushAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);
            observation.Mark("partial-handshake-flushed");
            await AssertPipeClosedAsync(stalled, observation);

            observation.Mark("later-status-start");
            Assert.Equal("healthy", (await client.GetStatusAsync(TestContext.Current.CancellationToken).ConfigureAwait(false)).Status);
            observation.Mark("later-status-asserted");
        }, stalledTransferTimeout: TimeSpan.FromMilliseconds(150), audit: audit, observation: observation);

        Assert.Contains(audit.Outcomes, item => item.Operation == "Connection" && item.ErrorCode is "ipc_transfer_timeout" or "connection_rejected");
    }

    [Fact]
    public async Task Partial_frame_after_handshake_releases_connection_and_allows_later_request()
    {
        CapturingAudit audit = new();
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            await using NamedPipeClientStream stalled = await ConnectRawPipeAsync(name, TestContext.Current.CancellationToken);
            _ = await PerformHandshakeAsync(stalled, TestContext.Current.CancellationToken).ConfigureAwait(false);
            await stalled.WriteAsync("B"u8.ToArray(), TestContext.Current.CancellationToken).ConfigureAwait(false);
            await stalled.FlushAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);
            await AssertPipeClosedAsync(stalled);

            Assert.Equal("healthy", (await client.GetStatusAsync(TestContext.Current.CancellationToken).ConfigureAwait(false)).Status);
        }, stalledTransferTimeout: TimeSpan.FromMilliseconds(150), audit: audit);

        Assert.Contains(audit.Outcomes, item => item.Operation == "Connection" && item.ErrorCode == "connection_rejected");
    }

    [Fact]
    public async Task Response_write_timeout_releases_connection_and_allows_later_request()
    {
        CapturingAudit audit = new();
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            await using NamedPipeClientStream stalled = await ConnectRawPipeAsync(name, TestContext.Current.CancellationToken);
            HandshakeResponse handshake = await PerformHandshakeAsync(stalled, TestContext.Current.CancellationToken).ConfigureAwait(false);
            for (ulong sequence = 1; sequence <= 8; sequence++)
            {
                Guid id = Guid.NewGuid();
                InvokeGatewayRequest invoke = new() { ConnectorId = "secure-layer-demo", OperationId = "submit", PayloadBase64 = "e30=" };
                await WriteBrokerRequestAsync(stalled, handshake, sequence, id, BrokerOperations.InvokeGateway, invoke, TestContext.Current.CancellationToken).ConfigureAwait(false);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(600), TestContext.Current.CancellationToken).ConfigureAwait(false);
            int receivedFrames = await ReadUntilClosedAsync(stalled).ConfigureAwait(false);
            Assert.InRange(receivedFrames, 0, 7);
            Assert.True((await client.GetStatusAsync(TestContext.Current.CancellationToken).ConfigureAwait(false)).GatewayConfigured);
        }, stalledTransferTimeout: TimeSpan.FromMilliseconds(150), gateway: new LargeGateway(), audit: audit);

        Assert.Contains(audit.Outcomes, item => item.Operation == BrokerOperations.InvokeGateway && item.Succeeded);
    }

    [Fact]
    public async Task Pipe_capacity_saturation_preserves_listener_and_authenticated_idle_connections()
    {
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            await using NamedPipeClientStream first = await ConnectRawPipeAsync(name, TestContext.Current.CancellationToken);
            await using NamedPipeClientStream second = await ConnectRawPipeAsync(name, TestContext.Current.CancellationToken);
            HandshakeResponse firstHandshake = await PerformHandshakeAsync(first, TestContext.Current.CancellationToken).ConfigureAwait(false);
            _ = await PerformHandshakeAsync(second, TestContext.Current.CancellationToken).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromMilliseconds(300), TestContext.Current.CancellationToken).ConfigureAwait(false);

            Guid id = Guid.NewGuid();
            await WriteBrokerRequestAsync(first, firstHandshake, 1, id, BrokerOperations.GetBrokerStatus, new { }, TestContext.Current.CancellationToken).ConfigureAwait(false);
            BrokerResponse response = await ReadBrokerResponseAsync(first, TestContext.Current.CancellationToken).ConfigureAwait(false);
            Assert.True(response.Success);

            await using NamedPipeClientStream third = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            using CancellationTokenSource connectTimeout = new(TimeSpan.FromMilliseconds(150));
            await Assert.ThrowsAsync<OperationCanceledException>(() => third.ConnectAsync(connectTimeout.Token));

            await second.DisposeAsync().ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromMilliseconds(150), TestContext.Current.CancellationToken).ConfigureAwait(false);
            Assert.Equal("healthy", (await client.GetStatusAsync(TestContext.Current.CancellationToken).ConfigureAwait(false)).Status);
        }, stalledTransferTimeout: TimeSpan.FromMilliseconds(100), maximumPipeInstances: 2);
    }

    [Fact]
    public async Task Same_connection_multiplexes_requests_and_honors_cancel_frame()
    {
        CapturingAudit audit = new();
        await WithBrokerAndPipeAsync(async (_, name) =>
        {
            await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(TestContext.Current.CancellationToken);
            Guid handshakeId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = "test-app", ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), TestContext.Current.CancellationToken);
            HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);

            BrokerRequest Request(Guid id, string operation, object body) => new()
            {
                Operation = operation,
                CorrelationId = id,
                ConnectionChallenge = handshake.ServerChallenge,
                RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
                DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(5),
                Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
            };

            Guid first = Guid.NewGuid();
            Guid second = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(first, 1, Request(first, BrokerOperations.GetBrokerStatus, new { })), TestContext.Current.CancellationToken);
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(second, 2, Request(second, BrokerOperations.GetBrokerStatus, new { })), TestContext.Current.CancellationToken);
            HashSet<Guid> responses = [];
            responses.Add(IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!).CorrelationId);
            responses.Add(IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!).CorrelationId);
            Assert.Equal(2, responses.Count);
            Assert.Contains(first, responses);
            Assert.Contains(second, responses);

            Guid slow = Guid.NewGuid();
            InvokeGatewayRequest invoke = new() { ConnectorId = "secure-layer-demo", OperationId = "submit", PayloadBase64 = "e30=" };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(slow, 3, Request(slow, BrokerOperations.InvokeGateway, invoke)), TestContext.Current.CancellationToken);
            await IpcFrameCodec.WriteAsync(pipe, new IpcFrame(IpcFrameType.Cancel, slow, 4, []), TestContext.Current.CancellationToken);
            BrokerResponse cancelled = IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);
            Assert.Equal("cancelled", cancelled.Error?.Code);
        }, gateway: new SlowGateway(), audit: audit);
        Assert.Equal(3, audit.Outcomes.Length);
        Assert.Equal(3, audit.Outcomes.Select(item => item.CorrelationId).Distinct().Count());
        Assert.Single(audit.Outcomes, item => !item.Succeeded && item.ErrorCode == "cancelled");
    }

    [Fact]
    public async Task Wire_errors_redact_invalid_payload_and_cryptographic_failure()
    {
        CapturingAudit audit = new();
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            ProtectedDataResult valid = await client.ProtectDataAsync(new ProtectDataRequest { Purpose = "redaction", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String("sensitive-plaintext"u8) }, TestContext.Current.CancellationToken);
            byte[] tampered = Convert.FromBase64String(valid.EnvelopeBase64);
            tampered[^1] ^= 1;

            await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(TestContext.Current.CancellationToken);
            Guid handshakeId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = "test-app", ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), TestContext.Current.CancellationToken);
            HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);

            BrokerRequest Request(Guid id, string operation, object body) => new()
            {
                Operation = operation,
                CorrelationId = id,
                ConnectionChallenge = handshake.ServerChallenge,
                RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
                DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(5),
                Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
            };

            const string invalidSensitiveValue = "sensitive-invalid-base64-value";
            Guid invalidId = Guid.NewGuid();
            ProtectDataRequest invalidBody = new() { Purpose = "redaction", ContentType = "text/plain", PlaintextBase64 = invalidSensitiveValue };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(invalidId, 1, Request(invalidId, BrokerOperations.ProtectData, invalidBody)), TestContext.Current.CancellationToken);
            IpcFrame invalidFrame = (await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!;
            string invalidWire = Encoding.UTF8.GetString(invalidFrame.Body);
            BrokerResponse invalidResponse = IpcFrameCodec.Deserialize<BrokerResponse>(invalidFrame);
            Assert.Equal("invalid_base64", invalidResponse.Error?.Code);
            Assert.DoesNotContain(invalidSensitiveValue, invalidWire, StringComparison.Ordinal);
            Assert.DoesNotContain("FormatException", invalidWire, StringComparison.Ordinal);
            Assert.DoesNotContain("C:\\", invalidWire, StringComparison.OrdinalIgnoreCase);

            Guid cryptoId = Guid.NewGuid();
            UnprotectDataRequest cryptoBody = new() { Purpose = "redaction", ContentType = "text/plain", EnvelopeBase64 = Convert.ToBase64String(tampered) };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(cryptoId, 2, Request(cryptoId, BrokerOperations.UnprotectData, cryptoBody)), TestContext.Current.CancellationToken);
            IpcFrame cryptoFrame = (await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!;
            string cryptoWire = Encoding.UTF8.GetString(cryptoFrame.Body);
            BrokerResponse cryptoResponse = IpcFrameCodec.Deserialize<BrokerResponse>(cryptoFrame);
            Assert.Equal("authentication_failed", cryptoResponse.Error?.Code);
            Assert.DoesNotContain(valid.EnvelopeBase64, cryptoWire, StringComparison.Ordinal);
            Assert.DoesNotContain("CryptographicException", cryptoWire, StringComparison.Ordinal);
        }, audit: audit);
        string auditText = string.Join("\n", audit.Events);
        Assert.DoesNotContain("sensitive", auditText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CryptographicException", auditText, StringComparison.Ordinal);
        Assert.Contains("invalid_base64", auditText, StringComparison.Ordinal);
        Assert.Contains("authentication_failed", auditText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Audit_logging_redacts_normal_and_authentication_denied_paths()
    {
        const string sensitive = "audit-sensitive-local-secret";
        CapturingAudit normalAudit = new();
        await WithBrokerAsync(async client =>
        {
            LocalSecretReference reference = await client.PutLocalSecretAsync(new PutLocalSecretRequest
            {
                LogicalName = "audit-key",
                SecretClass = "Tenant",
                ValueBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(sensitive)),
                AllowedOperations = ["ComputeHmac"],
            }, TestContext.Current.CancellationToken);
            _ = await client.ComputeHmacAsync(new ComputeHmacRequest { SecretRef = reference.SecretRef, MessageBase64 = Convert.ToBase64String("message"u8) }, TestContext.Current.CancellationToken);
            await client.DeleteLocalSecretAsync(new DeleteLocalSecretRequest { SecretRef = reference.SecretRef }, TestContext.Current.CancellationToken);
            await client.DeleteLocalSecretAsync(new DeleteLocalSecretRequest { SecretRef = reference.SecretRef }, TestContext.Current.CancellationToken);
            BrokerClientException missing = await Assert.ThrowsAsync<BrokerClientException>(() => client.ComputeHmacAsync(
                new ComputeHmacRequest { SecretRef = reference.SecretRef, MessageBase64 = "" }, TestContext.Current.CancellationToken));
            Assert.Equal("secret_not_found", missing.Code);
        }, audit: normalAudit);
        Assert.Equal(5, normalAudit.Outcomes.Length);
        Assert.Equal(5, normalAudit.Outcomes.Select(item => item.CorrelationId).Distinct().Count());
        Assert.Single(normalAudit.Outcomes, item => item.Operation == BrokerOperations.PutLocalSecret && item.Succeeded);
        Assert.Single(normalAudit.Outcomes, item => item.Operation == BrokerOperations.ComputeHmac && item.Succeeded);
        Assert.Equal(2, normalAudit.Outcomes.Count(item => item.Operation == BrokerOperations.DeleteLocalSecret && item.Succeeded));
        Assert.Single(normalAudit.Outcomes, item => item.Operation == BrokerOperations.ComputeHmac && !item.Succeeded && item.ErrorCode == "secret_not_found");
        Assert.DoesNotContain(sensitive, string.Join("\n", normalAudit.Events), StringComparison.Ordinal);

        CapturingAudit deniedAudit = new();
        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidHash: true, audit: deniedAudit));
        string deniedText = string.Join("\n", deniedAudit.Events);
        Assert.Equal("Connection", Assert.Single(deniedAudit.Outcomes).Operation);
        Assert.Contains("application_not_authorized", deniedText, StringComparison.Ordinal);
        Assert.DoesNotContain(Environment.ProcessPath!, deniedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(new string('0', 64), deniedText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Handshake_rejects_nonzero_sequence_and_malformed_nonce()
    {
        await WithBrokerAndPipeAsync(async (_, name) =>
        {
            async Task AssertRejectedAsync(ulong sequence, string nonce)
            {
                await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(TestContext.Current.CancellationToken);
                Guid correlation = Guid.NewGuid();
                HandshakeRequest request = new() { ApplicationRegistrationId = "test-app", ClientNonce = nonce };
                await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(correlation, sequence, request), TestContext.Current.CancellationToken);
                Assert.Null(await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken));
            }

            await AssertRejectedAsync(1, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            await AssertRejectedAsync(0, "not-base64");
        });
    }

    [Fact]
    public async Task Live_matrix_entry_point_resolves_helpers_in_clean_windows_powershell()
    {
        string repositoryRoot = FindRepositoryRoot();
        string powershell = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        string entryPoint = System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Invoke-LiveMatrix.ps1");
        Assert.True(File.Exists(powershell), $"Windows PowerShell 5.1 was not found at {powershell}.");
        Assert.True(File.Exists(entryPoint), $"Live matrix entry point was not found at {entryPoint}.");

        using Process process = new()
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = powershell,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(entryPoint);
        process.StartInfo.ArgumentList.Add("-Phase");
        process.StartInfo.ArgumentList.Add("ValidateHarness");
        process.StartInfo.ArgumentList.Add("-RunId");
        process.StartInfo.ArgumentList.Add("test-harness-" + Guid.NewGuid().ToString("N"));

        Assert.True(process.Start());
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        string output = await stdout;
        string error = await stderr;

        Assert.True(process.ExitCode == 0, $"Exit code {process.ExitCode}.{Environment.NewLine}STDOUT:{Environment.NewLine}{output}{Environment.NewLine}STDERR:{Environment.NewLine}{error}");
        using JsonDocument document = JsonDocument.Parse(output);
        JsonElement root = document.RootElement;
        Assert.Equal("HarnessValidated", root.GetProperty("overallStatus").GetString());
        Assert.True(root.GetProperty("helperResolutionPassed").GetBoolean());
        Assert.True(root.GetProperty("scriptParsePassed").GetBoolean());
        Assert.Contains(root.GetProperty("requiredExportedFunctions").EnumerateArray(), value => value.GetString() == "Get-WellKnownLiveMatrixSids");
    }

    [Fact]
    public void Live_matrix_local_user_descriptions_fit_windows_sam_limit()
    {
        string repositoryRoot = FindRepositoryRoot();
        string installScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Install-LiveBroker.ps1"));
        string[] descriptions =
        [
            "Secure Integration live matrix authorized",
            "Secure Integration live matrix denied",
        ];

        foreach (string description in descriptions)
        {
            Assert.InRange(description.Length, 1, 48);
            Assert.Contains($"-Description '{description}'", installScript, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Live_matrix_publish_restores_win_x64_assets_before_no_restore_publish()
    {
        string repositoryRoot = FindRepositoryRoot();
        string installScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Install-LiveBroker.ps1"));

        Assert.Contains("$runtimeLock = '-p:NuGetLockFilePath=obj\\live-matrix.win-x64.packages.lock.json'", installScript, StringComparison.Ordinal);
        Assert.Contains("& $dotnet restore $project --runtime win-x64 $runtimeLock", installScript, StringComparison.Ordinal);
        Assert.Contains("foreach ($project in $brokerProject, $probeProject)", installScript, StringComparison.Ordinal);
        Assert.Contains("& $dotnet publish $brokerProject --configuration Release --no-restore --runtime win-x64", installScript, StringComparison.Ordinal);
        Assert.Contains("& $dotnet publish $probeProject --configuration Release --no-restore --runtime win-x64", installScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Live_matrix_grants_and_revokes_batch_logon_for_synthetic_accounts()
    {
        string repositoryRoot = FindRepositoryRoot();
        string commonModule = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "LiveMatrix.Common.psm1"));
        string installScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Install-LiveBroker.ps1"));
        string cleanupScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Remove-LiveMatrix.ps1"));

        Assert.Contains("SeBatchLogonRight", commonModule, StringComparison.Ordinal);
        Assert.Contains("Grant-LiveMatrixBatchLogonRight -Sid $authorized.Sid", installScript, StringComparison.Ordinal);
        Assert.Contains("Grant-LiveMatrixBatchLogonRight -Sid $unauthorized.Sid", installScript, StringComparison.Ordinal);
        Assert.Contains("Revoke-LiveMatrixBatchLogonRight -Sid $user.Sid.Value", cleanupScript, StringComparison.Ordinal);
        Assert.Contains("Remove-EventLog -Source SecureIntegrationBroker", cleanupScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Live_matrix_stages_probe_results_in_the_account_exchange_before_preserving_raw_evidence()
    {
        string repositoryRoot = FindRepositoryRoot();
        string commonModule = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "LiveMatrix.Common.psm1"));

        Assert.Contains("$probeOutputPath = Join-Path (Split-Path -Parent $InputPath)", commonModule, StringComparison.Ordinal);
        Assert.Contains("-f $Command, $InputPath, $probeOutputPath", commonModule, StringComparison.Ordinal);
        Assert.Contains("[IO.File]::ReadAllText($probeOutputPath)", commonModule, StringComparison.Ordinal);
        Assert.Contains("[IO.File]::WriteAllText($OutputPath, $reportJson", commonModule, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $probeOutputPath -Force -ErrorAction SilentlyContinue", commonModule, StringComparison.Ordinal);
    }

    [Fact]
    public void Caller_identity_uses_limited_process_queries_for_cross_identity_clients()
    {
        string repositoryRoot = FindRepositoryRoot();
        string authorizationSource = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "src", "Broker", "Broker.Infrastructure.Windows", "ApplicationAuthorization.cs"));

        Assert.Contains("ProcessQueryLimitedInformation | Synchronize", authorizationSource, StringComparison.Ordinal);
        Assert.Contains("QueryFullProcessImageName", authorizationSource, StringComparison.Ordinal);
        Assert.Contains("GetProcessTimes", authorizationSource, StringComparison.Ordinal);
        Assert.Contains("pipe.RunAsClient", authorizationSource, StringComparison.Ordinal);
        Assert.DoesNotContain("process.SafeHandle", authorizationSource, StringComparison.Ordinal);
        Assert.DoesNotContain("process.MainModule", authorizationSource, StringComparison.Ordinal);
        Assert.DoesNotContain("OpenProcessToken", authorizationSource, StringComparison.Ordinal);
    }

    [Fact]
    public void Windows_service_uses_the_event_source_provisioned_by_the_installer()
    {
        string repositoryRoot = FindRepositoryRoot();
        string serviceProgram = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "src", "Broker", "Broker.Service", "Program.cs"));
        string installScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Install-LiveBroker.ps1"));

        Assert.Contains("Configure<EventLogSettings>", serviceProgram, StringComparison.Ordinal);
        Assert.Contains("settings.SourceName = \"SecureIntegrationBroker\"", serviceProgram, StringComparison.Ordinal);
        Assert.Contains("New-EventLog -LogName Application -Source SecureIntegrationBroker", installScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Live_matrix_accepts_the_synchronize_right_windows_adds_to_pipe_read_write()
    {
        string repositoryRoot = FindRepositoryRoot();
        string preRebootScript = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "live-matrix", "Invoke-PreReboot.ps1"));

        Assert.Contains("[IO.Pipes.PipeAccessRights]::ReadWrite -bor [IO.Pipes.PipeAccessRights]::Synchronize", preRebootScript, StringComparison.Ordinal);
        Assert.DoesNotContain("= 131483", preRebootScript, StringComparison.Ordinal);
    }

    private static async Task WithBrokerAsync(Func<BrokerClient, Task> test, bool invalidHash = false, bool invalidPublisher = false, TimeSpan? operationTimeout = null, IGatewayInvoker? gateway = null, IBrokerAuditSink? audit = null)
        => await WithBrokerAndPipeAsync((client, _) => test(client), invalidHash, invalidPublisher, operationTimeout, gateway, audit);

    private static async Task WithBrokerAndPipeAsync(
        Func<BrokerClient, string, Task> test,
        bool invalidHash = false,
        bool invalidPublisher = false,
        TimeSpan? operationTimeout = null,
        IGatewayInvoker? gateway = null,
        IBrokerAuditSink? audit = null,
        TimeSpan? stalledTransferTimeout = null,
        int? maximumPipeInstances = null,
        TimeoutObservation? observation = null)
    {
        using TestDirectory temporary = new();
        string pipeName = "SecureIntegration.Broker.Tests." + Guid.NewGuid().ToString("N");
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("The test host path is unavailable.");
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(executable, TestContext.Current.CancellationToken)));
        ApplicationPolicy policy = new()
        {
            RegistrationId = "test-app",
            AllowedUserSids = [sid],
            ExecutablePaths = [executable],
            ExecutableSha256 = [invalidHash ? new string('0', 64) : hash],
            AllowedPublisherThumbprints = invalidPublisher ? [new string('0', 40)] : [],
            AllowedOperations = [BrokerOperations.PutLocalSecret, BrokerOperations.DeleteLocalSecret, BrokerOperations.ComputeHmac, BrokerOperations.ProtectData, BrokerOperations.UnprotectData, BrokerOperations.GetBrokerStatus, BrokerOperations.InvokeGateway],
            GatewayGrants = ["secure-layer-demo:submit"],
            AllowedDataProtectionContexts = [new() { Purpose = CredentialExample.Purpose, ContentType = CredentialExample.ContentType },
                new() { Purpose = "test", ContentType = "text/plain" }, new() { Purpose = "redaction", ContentType = "text/plain" },
                .. Enumerable.Range(0, 8).Select(index => new DataProtectionContext { Purpose = "concurrent-" + index, ContentType = "application/octet-stream" })],
        };
        BrokerOptions options = new() { PipeName = pipeName, InstallationId = "test-installation", DataDirectory = temporary.Path, Applications = [policy] };
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        IBrokerAuditSink selectedAudit = audit ?? new NullAudit();
        await keys.InitializeAsync(TestContext.Current.CancellationToken);
        BrokerApplicationService application = new(secrets, protection, new AeadDataProtector(keys, options.InstallationId), options.InstallationId, gateway);
        await using NamedPipeBrokerServer server = stalledTransferTimeout is null && maximumPipeInstances is null
            ? new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(application), selectedAudit)
            : new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(application), selectedAudit,
                stalledTransferTimeout ?? TimeSpan.FromSeconds(5), maximumPipeInstances ?? 32);
        using CancellationTokenSource stopped = new();
        observation?.Mark("server-run-start");
        Task running = server.RunAsync(stopped.Token);
        observation?.Mark("server-run-returned");
        BrokerClientOptions clientOptions = new() { PipeName = pipeName, ApplicationRegistrationId = policy.RegistrationId };
        if (operationTimeout is not null) clientOptions.OperationTimeout = operationTimeout.Value;
        // Transport fixture, not a service qualification. Pin the test-owned kernel process and pipe owner.
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().Owner!;
        byte[] ownerBytes = new byte[owner.BinaryLength];
        owner.GetBinaryForm(ownerBytes, 0);
        BrokerClient client = new(clientOptions, () => new NamedPipeServerIdentity((uint)Environment.ProcessId, ownerBytes));
        try { await test(client, pipeName); }
        finally
        {
            observation?.Mark("server-stop-start");
            stopped.Cancel();
            await running;
            observation?.Mark("server-accept-loop-stopped");
        }
    }

    private static async Task<NamedPipeClientStream> ConnectRawPipeAsync(string name, CancellationToken cancellationToken)
    {
        NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.WriteThrough);
        try
        {
            await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<HandshakeResponse> PerformHandshakeAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        Guid handshakeId = Guid.NewGuid();
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest
        {
            ApplicationRegistrationId = "test-app",
            ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        }), cancellationToken).ConfigureAwait(false);
        IpcFrame frame = await IpcFrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) ?? throw new EndOfStreamException();
        Assert.Equal(handshakeId, frame.CorrelationId);
        Assert.Equal(0uL, frame.Sequence);
        return IpcFrameCodec.Deserialize<HandshakeResponse>(frame);
    }

    private static async Task WriteBrokerRequestAsync<TBody>(
        NamedPipeClientStream pipe,
        HandshakeResponse handshake,
        ulong sequence,
        Guid correlationId,
        string operation,
        TBody body,
        CancellationToken cancellationToken)
    {
        BrokerRequest request = new()
        {
            Operation = operation,
            CorrelationId = correlationId,
            ConnectionChallenge = handshake.ServerChallenge,
            RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
            DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(5),
            Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
        };
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(correlationId, sequence, request), cancellationToken).ConfigureAwait(false);
    }

    private static async Task<BrokerResponse> ReadBrokerResponseAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        IpcFrame frame = await IpcFrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) ?? throw new EndOfStreamException();
        return IpcFrameCodec.Deserialize<BrokerResponse>(frame);
    }

    private static async Task AssertPipeClosedAsync(NamedPipeClientStream pipe, TimeoutObservation? observation = null)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
        observation?.Mark("observer-deadline-start-3000ms");
        using CancellationTokenRegistration registration = observation is null ? default : timeout.Token.Register(() => observation.Mark("observer-deadline-cancelled"));
        try
        {
            Assert.Null(await IpcFrameCodec.ReadAsync(pipe, timeout.Token).ConfigureAwait(false));
            observation?.Mark("eof-asserted");
        }
        finally { observation?.Mark("eof-wait-exit"); }
    }

    private static async Task<int> ReadUntilClosedAsync(NamedPipeClientStream pipe)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        int frames = 0;
        while (await IpcFrameCodec.ReadAsync(pipe, timeout.Token).ConfigureAwait(false) is not null)
            frames++;
        return frames;
    }

    private sealed class SlowGateway : IGatewayInvoker
    {
        public async Task<GatewayInvocationResult> InvokeAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
            return new GatewayInvocationResult("application/json", [], "1");
        }
    }

    private sealed class LargeGateway : IGatewayInvoker
    {
        private static readonly byte[] ResponsePayload = Enumerable.Repeat((byte)'x', 600_000).ToArray();

        public Task<GatewayInvocationResult> InvokeAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken) =>
            Task.FromResult(new GatewayInvocationResult("application/octet-stream", ResponsePayload, "1"));
    }

    [Fact]
    public void M3_split_VM_harness_grants_batch_logon_and_install_execute_rights()
    {
        string repositoryRoot = FindRepositoryRoot();
        string runner = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "m3", "split-host", "Invoke-M3ASplitVm.ps1"));

        Assert.Contains("Grant-LiveMatrixBatchLogonRight -Sid $legacyUser.Sid", runner, StringComparison.Ordinal);
        Assert.Contains("Test-LiveMatrixBatchLogonRight -Sid $legacyUser.Sid", runner, StringComparison.Ordinal);
        Assert.Contains("Revoke-LiveMatrixBatchLogonRight -Sid $account.Sid.Value", runner, StringComparison.Ordinal);
        Assert.Contains("[Parameter(Mandatory)] [string] $LegacySid", runner, StringComparison.Ordinal);
        Assert.Contains("$legacyIdentifier, 'ReadAndExecute'", runner, StringComparison.Ordinal);
        Assert.Contains("Set-InstallAcl -Path $installRoot -ServiceSid $serviceSid -LegacySid $legacyUser.Sid", runner, StringComparison.Ordinal);
    }

    [Fact]
    public void M3_split_VM_harness_resolves_only_marker_owned_M0_M1_service_collisions()
    {
        string repositoryRoot = FindRepositoryRoot();
        string runner = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "m3", "split-host", "Invoke-M3ASplitVm.ps1"));

        Assert.Contains("function Remove-OwnedM0M1ServiceCollision", runner, StringComparison.Ordinal);
        Assert.Contains("SecureIntegration\\LiveMatrix\\Broker", runner, StringComparison.Ordinal);
        Assert.Contains("harness-owned-service.marker", runner, StringComparison.Ordinal);
        Assert.Contains("M3A_SPLIT_VM_REFUSE_FOREIGN_SERVICE_COLLISION", runner, StringComparison.Ordinal);
        Assert.Contains("& $cleanupScript -RunId $ownerRunId -Confirm:$false", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("$cleanupScript -RunId $ownerRunId -PurgeEvidence", runner, StringComparison.Ordinal);
    }

    [Fact]
    public void M3_split_VM_harness_uses_System_Version_compatible_broker_version()
    {
        string repositoryRoot = FindRepositoryRoot();
        string runner = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "m3", "split-host", "Invoke-M3ASplitVm.ps1"));

        Assert.True(Version.TryParse("3.0.0", out _));
        Assert.False(Version.TryParse("3.0.0-m3", out _));
        Assert.Contains("BrokerVersion = '3.0.0'", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("BrokerVersion = '3.0.0-m3'", runner, StringComparison.Ordinal);
    }

    [Fact]
    public void M3_split_VM_harness_emits_explicit_PASS_or_BLOCKED_result_archives()
    {
        string repositoryRoot = FindRepositoryRoot();
        string runner = File.ReadAllText(System.IO.Path.Combine(repositoryRoot, "tools", "m3", "split-host", "Invoke-M3ASplitVm.ps1"));

        Assert.Contains("Join-Path $evidenceDirectory 'RESULT.json'", runner, StringComparison.Ordinal);
        Assert.Contains("status = 'BLOCKED'", runner, StringComparison.Ordinal);
        Assert.Contains("classification = 'VM_RUN_FAILED'", runner, StringComparison.Ordinal);
        Assert.Contains("New-VmEvidenceArchive -Suffix '-failure' -Result $failureResult -ResultOnly", runner, StringComparison.Ordinal);
        Assert.Contains("status = 'PASS'", runner, StringComparison.Ordinal);
        Assert.Contains("classification = 'COMPLETED'", runner, StringComparison.Ordinal);
    }

    private sealed class NullAudit : IBrokerAuditSink
    {
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class CapturingAudit : IBrokerAuditSink
    {
        internal Action? ConnectionObserved { get; init; }
        private readonly System.Collections.Concurrent.ConcurrentQueue<AuditOutcome> events = new();
        public AuditOutcome[] Outcomes => events.ToArray();
        public IReadOnlyCollection<string> Events => events.Select(item => $"operation={item.Operation} application={item.ApplicationId} correlation={item.CorrelationId:D} succeeded={item.Succeeded} error={item.ErrorCode}").ToArray();
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken)
        {
            events.Enqueue(new(operation, applicationId, correlationId, succeeded, errorCode));
            if (operation == "Connection") ConnectionObserved?.Invoke();
            return Task.CompletedTask;
        }
    }

    private sealed record AuditOutcome(string Operation, string ApplicationId, Guid CorrelationId, bool Succeeded, string? ErrorCode);

    private sealed class TestDirectory : IDisposable
    {
        public TestDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "broker-gateway-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string Path { get; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(System.IO.Path.Combine(directory.FullName, "global.json"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
