namespace MyApi.Models.Permissions;

public sealed class UserPermissionsResponse
{
    [JsonPropertyName("userId")]
    public string UserId { get; init; } = string.Empty;

    [JsonPropertyName("fullName")]
    public string FullName { get; init; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("roles")]
    public IReadOnlyList<string> Roles { get; init; } = [];

    [JsonPropertyName("assignedPermissions")]
    public IReadOnlyList<string> AssignedPermissions { get; init; } = [];

    [JsonPropertyName("inheritedPermissions")]
    public IReadOnlyList<string> InheritedPermissions { get; init; } = [];

    [JsonPropertyName("effectivePermissions")]
    public IReadOnlyList<string> EffectivePermissions { get; init; } = [];

    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
}
