namespace MyApi.Controllers.Auth;

/// <summary>Lets Admin and Manager accounts manage direct permissions for registered users.</summary>
[ApiController]
[Authorize]
[Produces("application/json")]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status403Forbidden)]
[ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status500InternalServerError)]
public sealed class PermissionsController(IUserPermissionService permissionService) : ControllerBase
{
    private const string PermissionAdministrators = ApplicationRoles.Admin + "," + ApplicationRoles.Manager;

    /// <summary>Lists permission names that can be assigned to a user.</summary>
    [Authorize(Roles = PermissionAdministrators)]
    [HttpGet("[action]")]
    [ProducesResponseType(typeof(ApiResponse<IReadOnlyList<PermissionDefinitionResponse>>), StatusCodes.Status200OK)]
    public IActionResult GetAvailablePermissions()
    {
        var response = permissionService.GetAvailablePermissions();
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Returns the authenticated user's current direct, inherited, and effective permissions.</summary>
    [HttpGet("[action]")]
    [ProducesResponseType(typeof(ApiResponse<UserPermissionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetMyPermissions(CancellationToken cancellationToken)
    {
        var response = await permissionService.GetUserPermissionsAsync(User.GetUserId()!, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>Retrieves a registered user's permissions and the version needed when editing them.</summary>
    [Authorize(Roles = PermissionAdministrators)]
    [HttpGet("[action]/{userId}")]
    [ProducesResponseType(typeof(ApiResponse<UserPermissionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserPermissions(string userId, CancellationToken cancellationToken)
    {
        var response = await permissionService.GetUserPermissionsAsync(userId, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }

    /// <summary>
    /// Replaces the user's direct permissions. Send [] to revoke all direct grants.
    /// Role-inherited permissions are reported separately and cannot be removed here.
    /// </summary>
    [Authorize(Roles = PermissionAdministrators)]
    [HttpPut("[action]/{userId}")]
    [ProducesResponseType(typeof(ApiResponse<UserPermissionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> UpdateUserPermissions(
        string userId, [FromBody] UpdateUserPermissionsRequest request, CancellationToken cancellationToken)
    {
        var response = await permissionService.UpdateUserPermissionsAsync(
            userId, request, User.GetUserId()!, cancellationToken);
        return StatusCode(response.StatusCode, response);
    }
}
