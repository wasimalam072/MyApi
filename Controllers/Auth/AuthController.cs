namespace MyApi.Controllers.Auth;

/// <summary>
/// Handles user authentication and account registration.
/// </summary>
[ApiController]
[Produces("application/json")]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Creates a new application user account.
    /// </summary>
    /// <param name="request">
    /// Registration information provided by the user.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancels the request if the client disconnects
    /// or the request is aborted.
    /// </param>
    [AllowAnonymous]
    [HttpPost("[action]")]
    [ProducesResponseType(typeof(ApiResponse<RegisterResponse>), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        ApiResponse<RegisterResponse> response = await _authService.RegisterAsync(request, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }

    /// <summary>
    /// Authenticates a registered user and returns
    /// an access token when authentication succeeds.
    /// </summary>
    /// <param name="request">
    /// User login credentials.
    /// </param>
    /// <param name="cancellationToken">
    /// Cancels the request if the client disconnects
    /// or the request is aborted.
    /// </param>
    [AllowAnonymous]
    [HttpPost("[action]")]
    [ProducesResponseType(typeof(ApiResponse<LoginResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status423Locked)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        ApiResponse<LoginResponse> response = await _authService.LoginAsync(request, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }
}
