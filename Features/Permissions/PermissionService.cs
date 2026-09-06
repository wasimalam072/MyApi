namespace MyApi.Features.Permissions;

/// <summary>
/// Calculates the effective permissions available to an application user.
/// 
/// Effective permissions include:
/// - Permissions assigned directly to the user.
/// - Permissions inherited through Identity roles.
/// </summary>
public sealed class PermissionService : IPermissionService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<PermissionService> _logger;

    public PermissionService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<PermissionService> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
    }

    /// <summary>
    /// Returns all permissions available to the user.
    ///
    /// Permissions can come from two places:
    ///
    /// 1. Claims assigned directly to the user.
    /// 2. Claims assigned to any role that the user belongs to.
    ///
    /// Duplicate permissions are removed before the result is returned.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        cancellationToken.ThrowIfCancellationRequested();

// HashSet automatically prevents duplicate permissions.
        var permissions =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

                await AddUserPermissionsAsync(
            user,
            permissions,
            cancellationToken);

        await AddRolePermissionsAsync(
            user,
            permissions,
            cancellationToken);

        return permissions
            .OrderBy(permission => permission)
            .ToList();
    }

    /// <summary>
    /// Adds permissions that are assigned directly to the user.
    /// </summary>
    private async Task AddUserPermissionsAsync(
        ApplicationUser user,
        ISet<string> permissions,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        IList<Claim> claims =
            await _userManager.GetClaimsAsync(user);

        foreach (Claim claim in claims)
        {
            if (!IsPermissionClaim(claim))
            {
                continue;
            }

            permissions.Add(claim.Value);
        }
    }

/// <summary>
    /// Adds permissions inherited from every role assigned to the user.
    /// </summary>
    private async Task AddRolePermissionsAsync(
        ApplicationUser user,
        ISet<string> permissions,
        CancellationToken cancellationToken)
    {
        IList<string> roleNames =
            await _userManager.GetRolesAsync(user);

        foreach (string roleName in roleNames)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IdentityRole? role =
                await _roleManager.FindByNameAsync(roleName);

            if (role is null)
            {
                _logger.LogWarning(
                    "Role {RoleName} assigned to UserId={UserId} could not be found.",
                    roleName,
                    user.Id);

                continue;
            }

            IList<Claim> claims =
                await _roleManager.GetClaimsAsync(role);

            foreach (Claim claim in claims)
            {
                if (!IsPermissionClaim(claim))
                {
                    continue;
                }

                permissions.Add(claim.Value);
            }
        }
    }
    
    /// <summary>
    /// Determines whether a claim represents a valid
    /// application permission.
    /// </summary>
    private static bool IsPermissionClaim(
        Claim claim)
    {
        return claim.Type == CustomClaimTypes.Permission
               && !string.IsNullOrWhiteSpace(claim.Value);
    }
}