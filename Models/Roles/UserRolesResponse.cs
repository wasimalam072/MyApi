namespace MyApi.Models.Roles;

public sealed class UserRolesResponse
{
    [JsonPropertyName("userId")]
    public string UserId { get; init; } = string.Empty;

    [JsonPropertyName("fullName")]
    public string FullName { get; init; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("roles")]
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>Effective direct and inherited permissions, limited by the user's current roles.</summary>
    [JsonPropertyName("permissions")]
    public IReadOnlyList<string> Permissions { get; init; } = [];

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
}
