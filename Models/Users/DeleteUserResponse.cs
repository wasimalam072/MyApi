namespace MyApi.Models.Users;

public sealed class DeleteUserResponse
{
    [JsonPropertyName("userId")]
    public string UserId { get; init; } = string.Empty;

    [JsonPropertyName("deletedAtUtc")]
    public DateTimeOffset DeletedAtUtc { get; init; }
}