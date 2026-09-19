namespace MyApi.Controllers.Auth;

[ApiController]
[Authorize]
[Produces("application/json")]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
public sealed class RolesController(IUserRoleService roleService) : ControllerBase
{
    private const string RoleAdministrators = ApplicationRoles.Admin + "," + ApplicationRoles.Manager;

    /// <summary>Lists the three supported application roles and their current permissions.</summary>
    [Authorize(Roles = RoleAdministrators)]
    [HttpGet("[action]")]
    [ProducesResponseType(typeof(ApiResponse<IReadOnlyList<RoleDefinitionResponse>>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAvailableRoles(CancellationToken cancellationToken)
    {
        var response = await roleService.GetAvailableRolesAsync(cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Returns the authenticated user's current roles and effective permissions.</summary>
    [HttpGet("[action]")]
    [ProducesResponseType(typeof(ApiResponse<UserRolesResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetMyRoles(CancellationToken cancellationToken)
    {
        var response = await roleService.GetUserRolesAsync(User.GetUserId()!, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Returns a user's roles, effective permissions, and the version required to edit roles.</summary>
    [Authorize(Roles = RoleAdministrators)]
    [HttpGet("[action]/{userId}")]
    [ProducesResponseType(typeof(ApiResponse<UserRolesResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserRoles(string userId, CancellationToken cancellationToken)
    {
        var response = await roleService.GetUserRolesAsync(userId, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>
    /// Replaces a user's roles. Only Admins may grant Admin or Manager or edit privileged accounts.
    /// Managers may assign or remove User on ordinary accounts. Send [] to remove all roles.
    /// </summary>
    [Authorize(Roles = RoleAdministrators)]
    [HttpPut("[action]/{userId}")]
    [ProducesResponseType(typeof(ApiResponse<UserRolesResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> UpdateUserRoles(
        string userId, [FromBody] UpdateUserRolesRequest request, CancellationToken cancellationToken)
    {
        var response = await roleService.UpdateUserRolesAsync(
            userId, request, User.GetUserId()!, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }
}
