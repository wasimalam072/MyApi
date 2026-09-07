namespace MyApi.Features.Permissions;

public sealed class UserPermissionService(
    ApplicationDbContext database,
    ILogger<UserPermissionService> logger) : IUserPermissionService
{
    private static readonly IReadOnlyDictionary<string, string> PermissionNames = ApplicationPermissions.All
        .ToDictionary(name => name, name => name, StringComparer.OrdinalIgnoreCase);

    private static readonly IReadOnlyList<PermissionDefinitionResponse> Catalog = Array.AsReadOnly(
        ApplicationPermissions.All.Select(name => new PermissionDefinitionResponse(name, name switch
        {
            ApplicationPermissions.UsersView => "View registered user accounts.",
            ApplicationPermissions.UsersCreate => "Create accounts through user management.",
            ApplicationPermissions.UsersUpdate => "Update registered users' names and phone numbers.",
            ApplicationPermissions.UsersDelete => "Delete registered user accounts.",
            _ => name
        })).ToArray());

    public ApiResponse<IReadOnlyList<PermissionDefinitionResponse>> GetAvailablePermissions() =>
        ApiResponse<IReadOnlyList<PermissionDefinitionResponse>>.CreateSuccess(
            StatusCodes.Status200OK, "Available permissions retrieved.", Catalog, CreateTraceId());

    public async Task<ApiResponse<UserPermissionsResponse>> GetUserPermissionsAsync(
        string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string traceId = CreateTraceId();
        if (string.IsNullOrWhiteSpace(userId)) return InvalidUserId(traceId);

        ApplicationUser? user = await database.Users.AsNoTracking()
            .SingleOrDefaultAsync(user => user.Id == userId.Trim(), cancellationToken);
        if (user is null) return UserNotFound(traceId);

        string[] assigned = await database.UserClaims.AsNoTracking()
            .Where(claim => claim.UserId == user.Id && claim.ClaimType == CustomClaimTypes.Permission)
            .Select(claim => claim.ClaimValue!)
            .ToArrayAsync(cancellationToken);

        return ApiResponse<UserPermissionsResponse>.CreateSuccess(
            StatusCodes.Status200OK, "User permissions retrieved.",
            await MapResponseAsync(user, assigned, cancellationToken), traceId);
    }

    public async Task<ApiResponse<UserPermissionsResponse>> UpdateUserPermissionsAsync(
        string userId,
        UpdateUserPermissionsRequest request,
        string actingUserId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        string traceId = CreateTraceId();

        if (string.IsNullOrWhiteSpace(actingUserId))
        {
            return ApiResponse<UserPermissionsResponse>.CreateFailure(
                StatusCodes.Status401Unauthorized, "Please sign in again.",
                ErrorCodes.Authentication.UserIdMissing, traceId);
        }
        if (string.IsNullOrWhiteSpace(userId)) return InvalidUserId(traceId);
        if (string.IsNullOrWhiteSpace(request.Version) || request.Version.Length > 128)
        {
            return ApiResponse<UserPermissionsResponse>.CreateFailure(
                StatusCodes.Status400BadRequest, "Provide the version returned when retrieving user permissions.",
                ErrorCodes.UserPermissions.VersionRequired, traceId);
        }
        if (request.Permissions is null || request.Permissions.Length > 100)
        {
            return InvalidSelection("Provide a permissions array with at most 100 entries. Use [] to remove direct permissions.", traceId);
        }

        var desired = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string? permission in request.Permissions)
        {
            if (string.IsNullOrWhiteSpace(permission) || permission.Length > 128 ||
                !PermissionNames.TryGetValue(permission.Trim(), out string? canonicalName))
            {
                return InvalidSelection("Every permission must be a non-empty name from the available permissions list.", traceId);
            }
            desired.Add(canonicalName);
        }

        ApplicationUser? user = await database.Users
            .SingleOrDefaultAsync(user => user.Id == userId.Trim(), cancellationToken);
        if (user is null) return UserNotFound(traceId);
        if (!string.Equals(user.ConcurrencyStamp, request.Version, StringComparison.Ordinal))
        {
            return Conflict(traceId);
        }

        List<IdentityUserClaim<string>> currentClaims = await database.UserClaims
            .Where(claim => claim.UserId == user.Id && claim.ClaimType == CustomClaimTypes.Permission)
            .ToListAsync(cancellationToken);
        string[] assigned = Normalize(desired);

        // Only Permission claims are replaced. Other claims and all role grants
        // remain owned by their respective Identity workflows.
        if (!currentClaims.Select(claim => claim.ClaimValue).OrderBy(value => value, StringComparer.Ordinal)
            .SequenceEqual(assigned.OrderBy(value => value, StringComparer.Ordinal), StringComparer.Ordinal))
        {
            database.UserClaims.RemoveRange(currentClaims);
            database.UserClaims.AddRange(assigned.Select(permission => new IdentityUserClaim<string>
            {
                UserId = user.Id,
                ClaimType = CustomClaimTypes.Permission,
                ClaimValue = permission
            }));
            user.ConcurrencyStamp = Guid.NewGuid().ToString();

            try
            {
                // One SaveChanges transaction includes removals, additions, and
                // the optimistic concurrency check on the user's existing stamp.
                await database.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateConcurrencyException)
            {
                logger.LogWarning("Permission update conflicted. UserId={UserId} ActorId={ActorId} TraceId={TraceId}",
                    user.Id, actingUserId, traceId);
                return Conflict(traceId);
            }

            logger.LogInformation(
                "User permissions updated. UserId={UserId} ActorId={ActorId} Permissions={Permissions} TraceId={TraceId}",
                user.Id, actingUserId, assigned, traceId);
        }

        return ApiResponse<UserPermissionsResponse>.CreateSuccess(
            StatusCodes.Status200OK,
            "User permissions saved. Changes apply to the next authenticated request.",
            await MapResponseAsync(user, assigned, cancellationToken), traceId);
    }

    private async Task<UserPermissionsResponse> MapResponseAsync(
        ApplicationUser user, IEnumerable<string> assigned, CancellationToken cancellationToken)
    {
        string[] roles = await (
            from membership in database.UserRoles.AsNoTracking()
            join role in database.Roles.AsNoTracking() on membership.RoleId equals role.Id
            where membership.UserId == user.Id
            select role.Name!).ToArrayAsync(cancellationToken);

        string[] inherited = await (
            from membership in database.UserRoles.AsNoTracking()
            join claim in database.RoleClaims.AsNoTracking() on membership.RoleId equals claim.RoleId
            where membership.UserId == user.Id && claim.ClaimType == CustomClaimTypes.Permission
            select claim.ClaimValue!).ToArrayAsync(cancellationToken);

        string[] normalizedAssigned = Normalize(assigned);
        string[] normalizedInherited = Normalize(inherited);
        return new UserPermissionsResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            Roles = Normalize(roles),
            AssignedPermissions = normalizedAssigned,
            InheritedPermissions = normalizedInherited,
            EffectivePermissions = Normalize(normalizedAssigned.Concat(normalizedInherited)),
            Version = user.ConcurrencyStamp ?? string.Empty
        };
    }

    private static string[] Normalize(IEnumerable<string> values) => values
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static ApiResponse<UserPermissionsResponse> InvalidSelection(string message, string traceId) =>
        ApiResponse<UserPermissionsResponse>.CreateFailure(
            StatusCodes.Status400BadRequest, message, ErrorCodes.UserPermissions.InvalidSelection, traceId);

    private static ApiResponse<UserPermissionsResponse> InvalidUserId(string traceId) =>
        ApiResponse<UserPermissionsResponse>.CreateFailure(
            StatusCodes.Status400BadRequest, "A valid user ID is required.", ErrorCodes.Users.IdRequired, traceId);

    private static ApiResponse<UserPermissionsResponse> UserNotFound(string traceId) =>
        ApiResponse<UserPermissionsResponse>.CreateFailure(
            StatusCodes.Status404NotFound, "The requested user could not be found.", ErrorCodes.Users.NotFound, traceId);

    private static ApiResponse<UserPermissionsResponse> Conflict(string traceId) =>
        ApiResponse<UserPermissionsResponse>.CreateFailure(
            StatusCodes.Status409Conflict,
            "This user was changed by another request. Retrieve their current permissions and retry with the new version.",
            ErrorCodes.UserPermissions.Conflict, traceId);

    private static string CreateTraceId() => Activity.Current?.Id ?? Guid.NewGuid().ToString();
}
