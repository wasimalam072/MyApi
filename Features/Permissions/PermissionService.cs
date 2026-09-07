namespace MyApi.Features.Permissions;

/// <summary>
/// Combines permissions assigned directly to a user and inherited from their roles.
/// </summary>
public sealed class PermissionService : IPermissionService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<PermissionService> _logger;

    public PermissionService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ILogger<PermissionService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    public async Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        IList<string> roles = await _userManager.GetRolesAsync(user);
        return await GetEffectivePermissionsAsync(user, roles, cancellationToken);
    }

    public async Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(
        ApplicationUser user,
        IEnumerable<string> roles,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(roles);
        cancellationToken.ThrowIfCancellationRequested();

        var permissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddPermissions(permissions, await _userManager.GetClaimsAsync(user));

        // Identity managers share a scoped DbContext; role queries must remain sequential.
        foreach (string roleName in roles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            IdentityRole? role = await _roleManager.FindByNameAsync(roleName);
            if (role is null)
            {
                _logger.LogWarning(
                    "Role {RoleName} assigned to UserId={UserId} could not be found.", roleName, user.Id);
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            AddPermissions(permissions, await _roleManager.GetClaimsAsync(role));
        }

        cancellationToken.ThrowIfCancellationRequested();
        return permissions.OrderBy(permission => permission, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddPermissions(ISet<string> permissions, IEnumerable<Claim> claims)
    {
        foreach (Claim claim in claims)
        {
            if (claim.Type == CustomClaimTypes.Permission && !string.IsNullOrWhiteSpace(claim.Value))
            {
                permissions.Add(claim.Value);
            }
        }
    }
}
