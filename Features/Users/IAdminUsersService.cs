namespace MyApi.Features.Users;

public interface IAdminUsersService
{
    Task<ApiResponse<RegisterResponse>> CreateUserAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    Task<ApiResponse<RegisteredUserResponse>> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken cancellationToken = default);

    Task<ApiResponse<IReadOnlyList<RegisteredUserResponse>>> GetAllRegisteredUsersAsync(CancellationToken cancellationToken = default);

    Task<ApiResponse<DeleteUserResponse>> DeleteUserAsync(string userId, CancellationToken cancellationToken = default);
}
