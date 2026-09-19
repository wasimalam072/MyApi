namespace MyApi.Features.Roles;

/// <summary>Admins appoint Managers; Managers manage the User role on ordinary accounts.</summary>
public sealed class UserRoleService(
    ApplicationDbContext database,
    IPermissionService permissionService,
    ILogger<UserRoleService> logger) : IUserRoleService
{
    private static readonly IReadOnlyDictionary<string, string> RoleNames = ApplicationRoles.All
        .ToDictionary(name => name, name => name, StringComparer.OrdinalIgnoreCase);

    private static readonly IReadOnlyList<RoleDefinitionResponse> Catalog = Array.AsReadOnly(
        new RoleDefinitionResponse[]
        {
            new(ApplicationRoles.Admin, "Manage all user roles, appoint Managers, and administer users and permissions."),
            new(ApplicationRoles.Manager, "Create, view, and update user accounts; manage User roles and direct permissions."),
            new(ApplicationRoles.User, "View and update only your own profile.")
        });

    public async Task<ApiResponse<IReadOnlyList<RoleDefinitionResponse>>> GetAvailableRolesAsync(
        CancellationToken cancellationToken = default)
    {
        var claims = await (
            from claim in database.RoleClaims.AsNoTracking()
            join role in database.Roles.AsNoTracking() on claim.RoleId equals role.Id
            where claim.ClaimType == CustomClaimTypes.Permission && role.Name != null
            select new { RoleName = role.Name, Permission = claim.ClaimValue })
            .ToListAsync(cancellationToken);

        var permissionsByRole = claims.ToLookup(claim => claim.RoleName!, claim => claim.Permission,
            StringComparer.OrdinalIgnoreCase);
        RoleDefinitionResponse[] roles = Catalog.Select(role => role with
        {
            Permissions = RolePermissions.Constrain(
                permissionsByRole[role.Name].Where(permission => !string.IsNullOrWhiteSpace(permission))
                    .Select(permission => permission!), [role.Name])
        }).ToArray();

        return ApiResponse<IReadOnlyList<RoleDefinitionResponse>>.CreateSuccess(
            StatusCodes.Status200OK, "Available roles retrieved.", roles, CreateTraceId());
    }

    public async Task<ApiResponse<UserRolesResponse>> GetUserRolesAsync(
        string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string traceId = CreateTraceId();
        if (string.IsNullOrWhiteSpace(userId)) return InvalidUserId(traceId);

        ApplicationUser? user = await database.Users.AsNoTracking()
            .SingleOrDefaultAsync(user => user.Id == userId.Trim(), cancellationToken);
        if (user is null) return UserNotFound(traceId);

        return ApiResponse<UserRolesResponse>.CreateSuccess(
            StatusCodes.Status200OK, "User roles retrieved.",
            await MapResponseAsync(user, await GetRoleNamesAsync(user.Id, cancellationToken), cancellationToken), traceId);
    }

    public async Task<ApiResponse<UserRolesResponse>> UpdateUserRolesAsync(
        string userId,
        UpdateUserRolesRequest request,
        string actingUserId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        string traceId = CreateTraceId();

        if (string.IsNullOrWhiteSpace(actingUserId))
        {
            return ApiResponse<UserRolesResponse>.CreateFailure(
                StatusCodes.Status401Unauthorized, "Please sign in again.",
                ErrorCodes.Authentication.UserIdMissing, traceId);
        }
        if (string.IsNullOrWhiteSpace(userId)) return InvalidUserId(traceId);
        if (string.IsNullOrWhiteSpace(request.Version) || request.Version.Length > 128)
        {
            return ApiResponse<UserRolesResponse>.CreateFailure(
                StatusCodes.Status400BadRequest, "Provide the version returned when retrieving user roles.",
                ErrorCodes.UserRoles.VersionRequired, traceId);
        }
        if (request.Roles is null || request.Roles.Length > 100)
        {
            return InvalidSelection("Provide a roles array with at most 100 entries. Use [] to remove all roles.", traceId);
        }

        var desired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string? role in request.Roles)
        {
            if (string.IsNullOrWhiteSpace(role) || role.Length > 128 ||
                !RoleNames.TryGetValue(role.Trim(), out string? canonicalName))
            {
                return InvalidSelection("Every role must be Admin, Manager, or User.", traceId);
            }
            desired.Add(canonicalName);
        }

        // Use current database membership for the hierarchy, never role names supplied by the client.
        string[] actorRoles = await GetRoleNamesAsync(actingUserId, cancellationToken);
        bool isAdmin = actorRoles.Contains(ApplicationRoles.Admin, StringComparer.Ordinal);
        if (!isAdmin && !actorRoles.Contains(ApplicationRoles.Manager, StringComparer.Ordinal))
        {
            return Forbidden("Only Admin and Manager accounts can change user roles.", traceId);
        }
        if (!isAdmin && desired.Any(role => role != ApplicationRoles.User))
        {
            return Forbidden("Only an Admin can assign the Admin or Manager role.", traceId);
        }

        ApplicationUser? user = await database.Users
            .SingleOrDefaultAsync(user => user.Id == userId.Trim(), cancellationToken);
        if (user is null) return UserNotFound(traceId);

        List<IdentityUserRole<string>> memberships = await database.UserRoles
            .Where(membership => membership.UserId == user.Id).ToListAsync(cancellationToken);
        List<IdentityRole> availableRoles = await database.Roles.AsNoTracking().ToListAsync(cancellationToken);
        IdentityRole? userRole = availableRoles.SingleOrDefault(role => role.Name == ApplicationRoles.User);

        if (!isAdmin && memberships.Any(membership => membership.RoleId != userRole?.Id))
        {
            return Forbidden("Managers can only change roles on ordinary User accounts or accounts without roles.", traceId);
        }
        if (isAdmin && user.Id == actingUserId && !desired.Contains(ApplicationRoles.Admin))
        {
            return ApiResponse<UserRolesResponse>.CreateFailure(
                StatusCodes.Status403Forbidden, "You cannot remove your own Admin role. Ask another Admin to change it.",
                ErrorCodes.UserRoles.SelfDemotion, traceId);
        }
        if (!string.Equals(user.ConcurrencyStamp, request.Version, StringComparison.Ordinal))
        {
            return Conflict(traceId);
        }

        string[] assigned = desired.OrderBy(role => role, StringComparer.Ordinal).ToArray();
        var desiredRoleIds = availableRoles.Where(role => assigned.Contains(role.Name, StringComparer.Ordinal))
            .Select(role => role.Id).ToHashSet(StringComparer.Ordinal);
        if (desiredRoleIds.Count != assigned.Length)
        {
            return ApiResponse<UserRolesResponse>.CreateFailure(
                StatusCodes.Status500InternalServerError, "A required role is missing. Please contact the administrator.",
                ErrorCodes.Authentication.ConfigurationError, traceId);
        }

        var currentRoleIds = memberships.Select(membership => membership.RoleId).ToHashSet(StringComparer.Ordinal);
        if (!currentRoleIds.SetEquals(desiredRoleIds))
        {
            await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
            try
            {
                // Claim the user version first so competing edits, including identical
                // grants, fail with a concurrency conflict before inserting memberships.
                // Both saves commit together, so no intermediate role set is published.
                user.ConcurrencyStamp = Guid.NewGuid().ToString();
                await database.SaveChangesAsync(cancellationToken);

                database.UserRoles.RemoveRange(memberships.Where(membership => !desiredRoleIds.Contains(membership.RoleId)));
                database.UserRoles.AddRange(desiredRoleIds.Except(currentRoleIds).Select(roleId => new IdentityUserRole<string>
                {
                    UserId = user.Id,
                    RoleId = roleId
                }));
                await database.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch (DbUpdateConcurrencyException)
            {
                logger.LogWarning("Role update conflicted. UserId={UserId} ActorId={ActorId} TraceId={TraceId}",
                    user.Id, actingUserId, traceId);
                return Conflict(traceId);
            }

            logger.LogInformation(
                "User roles updated. UserId={UserId} ActorId={ActorId} Roles={Roles} TraceId={TraceId}",
                user.Id, actingUserId, assigned, traceId);
        }

        return ApiResponse<UserRolesResponse>.CreateSuccess(
            StatusCodes.Status200OK, "User roles saved. Changes apply to the next authenticated request.",
            await MapResponseAsync(user, assigned, cancellationToken), traceId);
    }

    private Task<string[]> GetRoleNamesAsync(string userId, CancellationToken cancellationToken) => (
        from membership in database.UserRoles.AsNoTracking()
        join role in database.Roles.AsNoTracking() on membership.RoleId equals role.Id
        where membership.UserId == userId
        orderby role.Name
        select role.Name!).ToArrayAsync(cancellationToken);

    private async Task<UserRolesResponse> MapResponseAsync(
        ApplicationUser user, IReadOnlyList<string> roles, CancellationToken cancellationToken) => new()
    {
        UserId = user.Id,
        FullName = user.FullName,
        Email = user.Email ?? string.Empty,
        Roles = roles,
        Permissions = await permissionService.GetEffectivePermissionsAsync(user, roles, cancellationToken),
        Version = user.ConcurrencyStamp ?? string.Empty
    };

    private static ApiResponse<UserRolesResponse> InvalidSelection(string message, string traceId) =>
        ApiResponse<UserRolesResponse>.CreateFailure(
            StatusCodes.Status400BadRequest, message, ErrorCodes.UserRoles.InvalidSelection, traceId);

    private static ApiResponse<UserRolesResponse> Forbidden(string message, string traceId) =>
        ApiResponse<UserRolesResponse>.CreateFailure(
            StatusCodes.Status403Forbidden, message, ErrorCodes.UserRoles.Forbidden, traceId);

    private static ApiResponse<UserRolesResponse> InvalidUserId(string traceId) =>
        ApiResponse<UserRolesResponse>.CreateFailure(
            StatusCodes.Status400BadRequest, "A valid user ID is required.", ErrorCodes.Users.IdRequired, traceId);

    private static ApiResponse<UserRolesResponse> UserNotFound(string traceId) =>
        ApiResponse<UserRolesResponse>.CreateFailure(
            StatusCodes.Status404NotFound, "The requested user could not be found.", ErrorCodes.Users.NotFound, traceId);

    private static ApiResponse<UserRolesResponse> Conflict(string traceId) =>
        ApiResponse<UserRolesResponse>.CreateFailure(
            StatusCodes.Status409Conflict,
            "This user was changed by another request. Retrieve their current roles and retry with the new version.",
            ErrorCodes.UserRoles.Conflict, traceId);

    private static string CreateTraceId() => Activity.Current?.Id ?? Guid.NewGuid().ToString();
}
