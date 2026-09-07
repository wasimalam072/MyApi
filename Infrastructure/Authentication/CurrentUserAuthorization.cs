namespace MyApi.Infrastructure.Authentication;

/// <summary>
/// Refreshes authorization after JWT signature/lifetime validation so permission
/// grants, revocations, and role changes apply to the next authenticated request.
/// </summary>
public sealed class CurrentUserAuthorization(
    UserManager<ApplicationUser> userManager,
    IPermissionService permissionService)
{
    public async Task RefreshAsync(TokenValidatedContext context)
    {
        string? userId = context.Principal?.GetUserId();
        if (string.IsNullOrWhiteSpace(userId) || context.Principal?.Identity is not ClaimsIdentity identity)
        {
            context.Fail("The token does not identify an application user.");
            return;
        }

        CancellationToken cancellationToken = context.HttpContext.RequestAborted;
        cancellationToken.ThrowIfCancellationRequested();
        ApplicationUser? user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            context.Fail("The account no longer exists.");
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        IList<string> roles = await userManager.GetRolesAsync(user);
        IReadOnlyList<string> permissions = await permissionService.GetEffectivePermissionsAsync(
            user, roles, cancellationToken);

        // Replace token snapshots instead of appending to them: revoked grants
        // and old administrative roles must not survive token validation.
        var currentIdentity = new ClaimsIdentity(
            identity.Claims.Where(claim => claim.Type != identity.RoleClaimType &&
                claim.Type != CustomClaimTypes.Permission),
            identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);
        currentIdentity.AddClaims(roles.Select(role => new Claim(currentIdentity.RoleClaimType, role)));
        currentIdentity.AddClaims(permissions.Select(permission => new Claim(CustomClaimTypes.Permission, permission)));
        context.Principal = new ClaimsPrincipal(currentIdentity);
    }
}
