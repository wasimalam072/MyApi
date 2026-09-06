namespace MyApi.Infrastructure.Authentication;

/// <summary>
/// Creates JWT access tokens for authenticated users.
/// </summary>
public sealed class TokenService : ITokenService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPermissionService _permissionService;
    private readonly JwtSettings _settings;

    public TokenService(
        UserManager<ApplicationUser> userManager,
        IPermissionService permissionService,
        IOptions<JwtSettings> options)
    {
        _userManager = userManager;
        _permissionService = permissionService;
        _settings = options.Value;
    }

    public async Task<TokenResult> CreateAccessTokenAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        DateTime expiresAtUtc =
            DateTime.UtcNow.AddMinutes(
                _settings.ExpirationMinutes);

        IList<string> roles =
            await _userManager.GetRolesAsync(user);

        IReadOnlyList<string> permissions =
            await _permissionService
                .GetEffectivePermissionsAsync(user, cancellationToken);

        List<Claim> claims =
        [
            new(
                JwtRegisteredClaimNames.Sub,
                user.Id),

            new(
                JwtRegisteredClaimNames.Email,
                user.Email ?? string.Empty),

            new(
                JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString()),

            new(
                ClaimTypes.NameIdentifier,
                user.Id),

            new(
                ClaimTypes.Name,
                user.UserName ?? string.Empty)
        ];

        // Role claims are used by:
        // [Authorize(Roles = "Admin")]
        claims.AddRange(
            roles.Select(
                role =>
                    new Claim(
                        ClaimTypes.Role,
                        role)));

        // Permission claims are used by authorization policies.
        claims.AddRange(
            permissions.Select(
                permission =>
                    new Claim(
                        CustomClaimTypes.Permission,
                        permission)));

        SymmetricSecurityKey signingKey =
            new(
                Encoding.UTF8.GetBytes(
                    _settings.Key));

        SigningCredentials credentials =
            new(
                signingKey,
                SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token =
            new(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                claims: claims, 
                notBefore: DateTime.UtcNow,
                expires: expiresAtUtc,
                signingCredentials: credentials);

        string accessToken =
            new JwtSecurityTokenHandler()
                .WriteToken(token);

        return new TokenResult
        {
            AccessToken = accessToken,
            ExpiresAtUtc = expiresAtUtc
        };
    }
}