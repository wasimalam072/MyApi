namespace MyApi.Models.Roles;

public sealed record RoleDefinitionResponse(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string Description)
{
    /// <summary>Permission claims currently granted by this role.</summary>
    [JsonPropertyName("permissions")]
    public IReadOnlyList<string> Permissions { get; init; } = [];
}
