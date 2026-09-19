namespace MyApi.Controllers.Users;

/// <summary>
/// Provides operations for the currently authenticated user.
/// </summary>
[ApiController]
[Authorize]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
public sealed class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    /// <summary>
    /// Returns the currently authenticated user's profile.
    /// </summary>
    [Authorize(Policy = Permissions.UsersView)]
    [HttpGet("[action]")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<RegisteredUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetCurrentUser(CancellationToken cancellationToken)
    {
        string? currentUserId = User.GetUserId();

        if (string.IsNullOrWhiteSpace(currentUserId))
        {
            return Unauthorized(
                new ApiResponse<object>
                {
                    StatusCode = StatusCodes.Status401Unauthorized,
                    Message = "Your authentication information is invalid. Please sign in again.",
                    ErrorCode = "AUTH_USER_ID_MISSING",
                    TraceId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
                });
        }

        ApiResponse<RegisteredUserResponse> response = await _userService.GetCurrentUserAsync(currentUserId, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }


    /// <summary>
    /// Updates the currently authenticated user's profile.
    /// </summary>
    [Authorize(Policy = Permissions.UsersUpdate)]
    [HttpPut("[action]")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<RegisteredUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> UpdateUser([FromBody] UpdateUserRequest request, CancellationToken cancellationToken)
    {
        string? currentUserId = User.GetUserId();

        if (string.IsNullOrWhiteSpace(currentUserId))
        {
            return Unauthorized(
                new ApiResponse<object>
                {
                    StatusCode = StatusCodes.Status401Unauthorized,
                    Message = "Your authentication information is invalid. Please sign in again.",
                    ErrorCode = "AUTH_USER_ID_MISSING",
                    TraceId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
                });
        }

        ApiResponse<RegisteredUserResponse> response = await _userService.UpdateUserAsync(currentUserId, request, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }
}
