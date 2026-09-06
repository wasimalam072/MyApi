namespace MyApi.Infrastructure.Authentication;

/// <summary>
/// Configuration used to validate API-key requests.
/// </summary>
public sealed class ApiKeySettings
{
    public const string SectionName = "ApiKeyAuthentication";

    public string HeaderName { get; init; } = "ApiKey";

    public string Key { get; init; } = string.Empty;
}