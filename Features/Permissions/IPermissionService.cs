namespace MyApi.Features.Permissions;

/// <summary>
/// Resolves permissions available to application users.
/// </summary>
public interface IPermissionService
{
    /// <summary>
    /// Returns all permissions available to a user from both
    /// direct user claims and claims inherited from assigned roles,
    /// limited to the permissions allowed by the user's current roles.
    /// </summary>
    Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves permissions without querying role names that the caller has already loaded.
    /// </summary>
    Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(
        ApplicationUser user,
        IEnumerable<string> roles,
        CancellationToken cancellationToken = default);
}
