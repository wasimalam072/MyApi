namespace MyApi.Models.Permissions;

public sealed class UpdateUserPermissionsRequest
{
    /// <summary>The version returned by GET permissions; prevents overwriting another edit.</summary>
    [Required]
    [StringLength(128)]
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    /// <summary>The complete desired set of direct permissions. An empty array revokes all direct grants.</summary>
    [Required]
    [MaxLength(100)]
    [JsonPropertyName("permissions")]
    public string[]? Permissions { get; init; }
}
