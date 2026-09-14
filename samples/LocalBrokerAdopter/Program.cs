using System.Diagnostics;
using System.Security.Cryptography;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;

const string Purpose = "adopter-secret";
const string ContentType = "text/plain";
byte[] expected = "local-broker-adopter-synthetic-v1"u8.ToArray();

if (args.Length != 5 || args[0] is not ("status" or "protect" or "verify" or "denied"))
{
    Console.Error.WriteLine("Usage: LocalBrokerAdopter <status|protect|verify|denied> <service> <pipe> <application> <envelope-file-or-dash>");
    return 2;
}

try
{
    Stopwatch elapsed = Stopwatch.StartNew();
    BrokerClient client = new(new BrokerClientOptions { ServiceName = args[1], PipeName = args[2], ApplicationRegistrationId = args[3] });
    using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));

    if (args[0] == "denied")
    {
        try { _ = await client.GetStatusAsync(deadline.Token); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine("UNAUTHORIZED_CLIENT=DENIED");
            return 0;
        }
        catch (BrokerClientException failure) when (failure.Code is "application_not_authorized" or "operation_not_granted") { Console.WriteLine("UNAUTHORIZED_CLIENT=DENIED"); return 0; }
        throw new InvalidOperationException("Unauthorized application was accepted.");
    }

    BrokerStatus status = await client.GetStatusAsync(deadline.Token);
    if (args[0] == "protect")
    {
        byte[] plaintext = expected.ToArray();
        try
        {
            ProtectedDataResult result = await client.ProtectDataAsync(new ProtectDataRequest
            {
                Purpose = Purpose,
                ContentType = ContentType,
                PlaintextBase64 = Convert.ToBase64String(plaintext),
            }, deadline.Token);
            await File.WriteAllBytesAsync(args[4], Convert.FromBase64String(result.EnvelopeBase64), deadline.Token);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    if (args[0] == "verify")
    {
        byte[] envelope = await File.ReadAllBytesAsync(args[4], deadline.Token);
        UnprotectedDataResult result = await client.UnprotectDataAsync(new UnprotectDataRequest
        {
            Purpose = Purpose,
            ContentType = ContentType,
            EnvelopeBase64 = Convert.ToBase64String(envelope),
        }, deadline.Token);
        byte[] recovered = Convert.FromBase64String(result.PlaintextBase64);
        try
        {
            if (!recovered.AsSpan().SequenceEqual(expected)) throw new InvalidOperationException("Roundtrip failed.");
            await ExpectDeniedAsync(client, "adopter-secret", "application/json", envelope, deadline.Token);
            await ExpectDeniedAsync(client, "other-purpose", ContentType, envelope, deadline.Token);
        }
        finally { CryptographicOperations.ZeroMemory(recovered); }
    }

    Console.WriteLine($"{args[0].ToUpperInvariant()}=PASS GATEWAY={(status.GatewayConfigured ? "ENABLED" : "DISABLED")} ELAPSED_MS={elapsed.ElapsedMilliseconds}");
    return 0;
}
catch (BrokerClientException exception)
{
    Console.Error.WriteLine($"{exception.Code} RETRYABLE={exception.Retryable}");
    return 1;
}
catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException or InvalidOperationException or FormatException or ArgumentException or System.Security.SecurityException)
{
    Console.Error.WriteLine("LOCAL_BROKER_ADOPTER_FAILED");
    return 1;
}

static async Task ExpectDeniedAsync(BrokerClient client, string purpose, string contentType, byte[] envelope, CancellationToken cancellationToken)
{
    try
    {
        _ = await client.UnprotectDataAsync(new UnprotectDataRequest
        {
            Purpose = purpose,
            ContentType = contentType,
            EnvelopeBase64 = Convert.ToBase64String(envelope),
        }, cancellationToken);
    }
    catch (BrokerClientException failure) when (failure.Code == "data_context_not_granted") { return; }

    throw new InvalidOperationException("Invalid context was accepted.");
}
