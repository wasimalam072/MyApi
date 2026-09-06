namespace MyApi.Models.Auth;

public sealed class RegisterResponse
{
    [JsonPropertyName("userId")]
    public string UserId { get; init; } = string.Empty;


    [JsonPropertyName("fullName")]
    public string FullName { get; init; } = string.Empty;


    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;


    [JsonPropertyName("phoneNumber")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PhoneNumber { get; init; }


    [JsonPropertyName("emailConfirmed")]
    public bool EmailConfirmed { get; init; }


    [JsonPropertyName("phoneNumberConfirmed")]
    public bool PhoneNumberConfirmed { get; init; }


    [JsonPropertyName("roles")]
    public IReadOnlyList<string> Roles { get; init; }
        = Array.Empty<string>();


    [JsonPropertyName("permissions")]
    public IReadOnlyList<string> Permissions { get; init; }
        = Array.Empty<string>();
}