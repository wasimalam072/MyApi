namespace MyApi.Features.Users;

public interface IUserService
{
    Task<ApiResponse<RegisteredUserResponse>> GetCurrentUserAsync(string currentUserId, CancellationToken cancellationToken = default);
    Task<ApiResponse<RegisteredUserResponse>> UpdateUserAsync(string currentUserId, UpdateUserRequest request, CancellationToken cancellationToken = default);
    }