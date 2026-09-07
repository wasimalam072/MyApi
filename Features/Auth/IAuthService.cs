namespace MyApi.Features.Auth;

/// <summary>
/// Defines account registration and password authentication.
/// Use one dependency-injection scope per request and await operations sequentially.
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
