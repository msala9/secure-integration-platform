using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Text.Json;

namespace SecureIntegration.TestDiagnostics;

// Temporary diagnostic branch only. No event payload, exception, request or identity is retained.
internal sealed class TimeoutObservation : IDisposable
{
    private static readonly AsyncLocal<TimeoutObservation?> Current = new();
    private readonly List<object> observations = [];
    private readonly long started = Stopwatch.GetTimestamp();
    private readonly string? directory = Environment.GetEnvironmentVariable("SIP_TIMEOUT_DIAGNOSTICS");
    private readonly string name;
    private readonly Timer? timer;
    private readonly NetworkEvents? network;
    private bool disposed;

    internal TimeoutObservation(string name)
    {
        this.name = name;
        if (directory is null) return;
        Current.Value = this;
        network = new NetworkEvents { Owner = this };
        Mark("test-start");
        timer = new Timer(_ => Mark("process-sample"), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    internal void Mark(string phase)
    {
        if (directory is null) return;
        lock (observations)
        {
            if (disposed || observations.Count >= 256) return;
            using Process process = Process.GetCurrentProcess();
            observations.Add(new
            {
                phase,
                utc = DateTimeOffset.UtcNow,
                elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                pid = Environment.ProcessId,
                cpuMs = process.TotalProcessorTime.TotalMilliseconds,
                workingSetBytes = process.WorkingSet64,
                privateBytes = process.PrivateMemorySize64,
                threadPoolThreads = ThreadPool.ThreadCount,
                pendingWorkItems = ThreadPool.PendingWorkItemCount
            });
        }
    }

    public void Dispose()
    {
        if (directory is null) return;
        timer?.Dispose();
        network?.Dispose();
        Mark("test-scope-exit");
        lock (observations)
        {
            disposed = true;
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, name + ".json"), JsonSerializer.Serialize(observations));
        }
        Current.Value = null;
    }

    private sealed class NetworkEvents : EventListener
    {
        internal TimeoutObservation? Owner { get; init; }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name is "System.Net.Http" or "System.Net.Security" or "System.Net.Sockets")
                EnableEvents(eventSource, EventLevel.Informational);
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (Owner is null || Current.Value != Owner) return;
            string? phase = eventData.EventName switch
            {
                "RequestStart" => "net-request-start",
                "RequestStop" => "net-request-stop",
                "RequestFailed" => "net-request-failed",
                "ConnectStart" => "net-connect-start",
                "ConnectStop" => "net-connect-stop",
                "ConnectFailed" => "net-connect-failed",
                "HandshakeStart" => "net-tls-start",
                "HandshakeStop" => "net-tls-stop",
                "HandshakeFailed" => "net-tls-failed",
                "RequestHeadersStart" => "net-request-headers-start",
                "RequestHeadersStop" => "net-request-headers-stop",
                "ResponseHeadersStart" => "net-response-headers-start",
                "ResponseHeadersStop" => "net-response-headers-stop",
                _ => null
            };
            if (phase is not null) Owner.Mark(phase);
        }
    }
}
