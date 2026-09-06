namespace MyApi.Controllers.Auth;

[ApiController]
[ApiVersion(VersionValue.Version_1)]
[Route("api/v{version:apiVersion}/[controller]")]
[Authorize( Roles = ApplicationRoles.Admin + "," + ApplicationRoles.Manager)]
public sealed class PermissionsController : ControllerBase
{
    private readonly IPermissionService _permissionService;

    public PermissionsController(IPermissionService permissionService)
    {
        _permissionService = permissionService;
    }
}