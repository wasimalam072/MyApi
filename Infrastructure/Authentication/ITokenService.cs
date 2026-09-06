namespace MyApi.Infrastructure.Authentication;

public interface ITokenService
{
    Task<TokenResult> CreateAccessTokenAsync(ApplicationUser user, CancellationToken cancellationToken = default);
}