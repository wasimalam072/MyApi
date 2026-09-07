namespace MyApi.Features.Permissions;

/// <summary>Manages direct user grants separately from role-inherited permissions.</summary>
public interface IUserPermissionService
{
    ApiResponse<IReadOnlyList<PermissionDefinitionResponse>> GetAvailablePermissions();

    Task<ApiResponse<UserPermissionsResponse>> GetUserPermissionsAsync(
        string userId, CancellationToken cancellationToken = default);

    Task<ApiResponse<UserPermissionsResponse>> UpdateUserPermissionsAsync(
        string userId,
        UpdateUserPermissionsRequest request,
        string actingUserId,
        CancellationToken cancellationToken = default);
}
