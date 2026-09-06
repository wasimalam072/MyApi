namespace MyApi.Features.Users;

public interface IAdminUsersService
{
    Task<ApiResponse<IReadOnlyList<RegisteredUserResponse>>> GetAllRegisteredUsersAsync(
        CancellationToken cancellationToken = default);

    Task<ApiResponse<DeleteUserResponse>> DeleteUserAsync(
        string userId,
        CancellationToken cancellationToken = default);
}