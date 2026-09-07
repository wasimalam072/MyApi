namespace MyApi.Features.Users;

/// <summary>
/// Maps profiles consistently for current-user and administrative endpoints.
/// </summary>
public sealed class UserResponseMapper : IUserResponseMapper
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPermissionService _permissionService;

    public UserResponseMapper(
        UserManager<ApplicationUser> userManager,
        IPermissionService permissionService)
    {
        _userManager = userManager;
        _permissionService = permissionService;
    }

    public async Task<RegisteredUserResponse> MapAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        IReadOnlyList<string> roles = (await _userManager.GetRolesAsync(user))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(role => role, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        IReadOnlyList<string> permissions = await _permissionService.GetEffectivePermissionsAsync(
            user, roles, cancellationToken);

        return new RegisteredUserResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            Roles = roles,
            Permissions = permissions
        };
    }
}
