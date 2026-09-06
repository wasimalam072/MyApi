namespace MyApi.Models;

public sealed class TokenResult
{
    public string AccessToken { get; init; } = string.Empty;
    public DateTime ExpiresAtUtc { get; init; }
}