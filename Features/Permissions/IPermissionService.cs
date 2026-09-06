namespace MyApi.Features.Permissions;

/// <summary>
/// Resolves permissions available to application users.
/// </summary>
public interface IPermissionService
{
    /// <summary>
    /// Returns all permissions available to a user from both
    /// direct user claims and claims inherited from assigned roles.
    /// </summary>
    Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(ApplicationUser user, CancellationToken cancellationToken = default);
}