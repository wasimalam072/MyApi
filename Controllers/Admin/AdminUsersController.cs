namespace MyApi.Controllers.Admin;

[ApiController]
[Authorize(Roles = ApplicationRoles.Admin + "," + ApplicationRoles.Manager)]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
public sealed class AdminUsersController : ControllerBase
{
    private readonly IAdminUsersService _adminUsersService;

    public AdminUsersController(IAdminUsersService adminUsersService)
    {
        _adminUsersService = adminUsersService;
    }

    /// <summary>
    /// Returns all registered application users.
    ///
    /// Requires Admin or Manager and the Users.View permission.
    /// </summary>
    [Authorize(Policy = Permissions.UsersView)]
    [HttpGet("[action]")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<IReadOnlyList<RegisteredUserResponse>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> AllRegisteredUsers(CancellationToken cancellationToken)
    {
        ApiResponse<IReadOnlyList<RegisteredUserResponse>> response = await _adminUsersService.GetAllRegisteredUsersAsync(cancellationToken);

        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Creates a standard user account when the caller has Users.Create.</summary>
    [Authorize(Policy = Permissions.UsersCreate)]
    [HttpPost("[action]")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<RegisterResponse>), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> CreateUser([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        var response = await _adminUsersService.CreateUserAsync(request, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Updates a registered user's name and phone when the caller has Users.Update.</summary>
    [Authorize(Policy = Permissions.UsersUpdate)]
    [HttpPut("[action]/{userId}")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<RegisteredUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> UpdateUser(string userId, [FromBody] UpdateUserRequest request, CancellationToken cancellationToken)
    {
        var response = await _adminUsersService.UpdateUserAsync(userId, request, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>
    /// Permanently deletes a user account.
    /// </summary>
    /// <param name="userId">
    /// Identity identifier of the user that will be deleted.
    /// </param>
    [Authorize(Policy = Permissions.UsersDelete)]
    [Authorize(Roles = ApplicationRoles.Admin)]
    [HttpDelete("[action]/{userId}")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<DeleteUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> DeleteUser([FromRoute] string userId, CancellationToken cancellationToken)
    {
        ApiResponse<DeleteUserResponse> response = await _adminUsersService.DeleteUserAsync(userId, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }
}
