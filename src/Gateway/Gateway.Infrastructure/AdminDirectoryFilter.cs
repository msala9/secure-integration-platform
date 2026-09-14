using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

internal static class AdminDirectoryFilter
{
    internal static string Normalize(string? filter)
    {
        if (filter?.Length > 100) throw new GatewayException("BGW-ADMIN-PAGINATION", 400);
        return filter?.Trim() ?? string.Empty;
    }

    internal static bool Matches(string code, string name, string filter) =>
        code.Contains(filter, StringComparison.OrdinalIgnoreCase) || name.Contains(filter, StringComparison.OrdinalIgnoreCase);
}
