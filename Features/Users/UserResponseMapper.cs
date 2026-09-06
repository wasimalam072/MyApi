namespace MyApi.Features.Users;

/// <summary>
/// Converts Identity users into API response models.
///
/// Keeping this mapping in one place ensures that user responses
/// are consistent across normal-user and administrative endpoints.
/// </summary>
public sealed class UserResponseMapper
    : IUserResponseMapper
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

        IList<string> roles =
            await _userManager.GetRolesAsync(user);

                IReadOnlyList<string> permissions =
            await _permissionService
                .GetEffectivePermissionsAsync(
                    user,
                    cancellationToken);

        return new RegisteredUserResponse
        {
            UserId =
                user.Id,

            FullName =
                user.FullName,

            Email =
                user.Email ?? string.Empty,

            PhoneNumber =
                user.PhoneNumber,

            EmailConfirmed =
                user.EmailConfirmed,

            PhoneNumberConfirmed =
                user.PhoneNumberConfirmed,

            Roles =
                roles
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .OrderBy(
                        role => role)
                    .ToList(),

            Permissions =
                permissions
        };
    }
}