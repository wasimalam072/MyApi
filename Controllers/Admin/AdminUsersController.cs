namespace MyApi.Controllers.Admin;

[ApiController]
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
    /// The caller must be an Admin or Manager and must have
    /// the Users.View permission.
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

    /// <summary>
    /// Permanently deletes a user account.
    /// </summary>
    /// <param name="userId">
    /// Identity identifier of the user that will be deleted.
    /// </param>
    [Authorize(Policy = Permissions.UsersDelete)]
    [HttpDelete("[action]/{userId}")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(ApiResponse<DeleteUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<DeleteUserResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<DeleteUserResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> DeleteUser([FromRoute] string userId, CancellationToken cancellationToken)
    {
        ApiResponse<DeleteUserResponse> response = await _adminUsersService.DeleteUserAsync(userId, cancellationToken);

        return StatusCode(response.StatusCode, response);
    }
}