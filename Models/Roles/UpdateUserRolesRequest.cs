namespace MyApi.Models.Roles;

public sealed class UpdateUserRolesRequest
{
    /// <summary>The version returned by GET roles; prevents overwriting another edit.</summary>
    [Required]
    [StringLength(128)]
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    /// <summary>The complete desired role set. An empty array removes all roles.</summary>
    [Required]
    [MaxLength(100)]
    [JsonPropertyName("roles")]
    public string[]? Roles { get; init; }
}
