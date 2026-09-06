namespace MyApi.Features.Auth;

/// <summary>
/// Defines authentication operations such as
/// user registration and login.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Registers a new application user.
    /// </summary>
    Task<ApiResponse<RegisterResponse>> RegisterAsync(
        RegisterRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates a user and returns login information
    /// including the access token.
    /// </summary>
    Task<ApiResponse<LoginResponse>> LoginAsync(
        LoginRequest request,
        CancellationToken cancellationToken = default);
}