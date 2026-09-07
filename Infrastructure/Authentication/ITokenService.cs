namespace MyApi.Infrastructure.Authentication;

public interface ITokenService
{
    /// <summary>
    /// Signs a token without database access, using the same roles and permissions as the login response.
    /// </summary>
    TokenResult CreateAccessToken(
        ApplicationUser user,
        IReadOnlyList<string> roles,
        IReadOnlyList<string> permissions);
}
