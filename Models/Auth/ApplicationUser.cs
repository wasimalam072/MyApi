namespace MyApi.Models.Auth;

public sealed class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}