namespace MyApi.Features.Roles;

public interface IUserRoleService
{
    Task<ApiResponse<IReadOnlyList<RoleDefinitionResponse>>> GetAvailableRolesAsync(
        CancellationToken cancellationToken = default);

    Task<ApiResponse<UserRolesResponse>> GetUserRolesAsync(
        string userId, CancellationToken cancellationToken = default);

    Task<ApiResponse<UserRolesResponse>> UpdateUserRolesAsync(
        string userId,
        UpdateUserRolesRequest request,
        string actingUserId,
        CancellationToken cancellationToken = default);
}
