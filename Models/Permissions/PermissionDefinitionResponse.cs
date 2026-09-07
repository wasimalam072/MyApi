namespace MyApi.Models.Permissions;

public sealed record PermissionDefinitionResponse(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string Description);
