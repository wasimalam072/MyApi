namespace MyApi.Features.Users;

public sealed class AdminUsersService : IAdminUsersService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserResponseMapper _userResponseMapper;
    private readonly ILogger<AdminUsersService> _logger;
    private readonly IAuthService _authService;
    private readonly IUserService _userService;

    public AdminUsersService(
        UserManager<ApplicationUser> userManager,
        IUserResponseMapper userResponseMapper,
        ILogger<AdminUsersService> logger,
        IAuthService authService,
        IUserService userService)
    {
        _userManager = userManager;
        _userResponseMapper = userResponseMapper;
        _logger = logger;
        _authService = authService;
        _userService = userService;
    }

    public Task<ApiResponse<RegisterResponse>> CreateUserAsync(
        RegisterRequest request, CancellationToken cancellationToken = default) =>
        _authService.RegisterAsync(request, cancellationToken);

    public async Task<ApiResponse<RegisteredUserResponse>> UpdateUserAsync(
        string userId, UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(userId))
        {
            return ApiResponse<RegisteredUserResponse>.CreateFailure(
                StatusCodes.Status400BadRequest, "A valid user ID is required.",
                ErrorCodes.Users.IdRequired, Activity.Current?.Id);
        }

        var response = await _userService.UpdateUserAsync(userId, request, cancellationToken);
        return response.Success
            ? ApiResponse<RegisteredUserResponse>.CreateSuccess(
                response.StatusCode, "User profile updated successfully.", response.Data, response.TraceId)
            : response;
    }

    public async Task<ApiResponse<IReadOnlyList<RegisteredUserResponse>>> GetAllRegisteredUsersAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string traceId =
            Activity.Current?.Id
            ?? Guid.NewGuid().ToString();

        _logger.LogInformation(
            "Retrieving registered users. TraceId={TraceId}",
            traceId);

        List<ApplicationUser> users =
            await _userManager.Users
                .AsNoTracking()
                .OrderBy(user => user.FullName)
                .ThenBy(user => user.Email)
                .ToListAsync(cancellationToken);

        var registeredUsers =
            new List<RegisteredUserResponse>(
                users.Count);

        foreach (ApplicationUser user in users)
        {
            cancellationToken.ThrowIfCancellationRequested();

            RegisteredUserResponse response =
                await _userResponseMapper.MapAsync(
                    user,
                    cancellationToken);

            registeredUsers.Add(response);
        }

        _logger.LogInformation(
            "Registered users retrieved successfully. Count={Count} TraceId={TraceId}",
            registeredUsers.Count,
            traceId);

        return ApiResponse<
                IReadOnlyList<RegisteredUserResponse>>
            .CreateSuccess(
                StatusCodes.Status200OK,
                registeredUsers.Count == 0
                    ? "No registered users were found."
                    : $"{registeredUsers.Count} registered user(s) retrieved successfully.",
                registeredUsers,
                traceId);
    }

    public async Task<ApiResponse<DeleteUserResponse>> DeleteUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string traceId =
            Activity.Current?.Id
            ?? Guid.NewGuid().ToString();

        // -------------------------------------------------------
        // VALIDATE USER ID
        // -------------------------------------------------------

        if (string.IsNullOrWhiteSpace(userId))
        {
            _logger.LogWarning(
                "Delete user rejected because UserId was empty. TraceId={TraceId}",
                traceId);

            return ApiResponse<DeleteUserResponse>
    .CreateFailure(
        StatusCodes.Status400BadRequest,
        "A valid user ID is required.",
        ErrorCodes.Users.IdRequired,
        traceId);
        }

        string normalizedUserId =
            userId.Trim();

        // -------------------------------------------------------
        // DELETE STARTED
        // -------------------------------------------------------

        _logger.LogInformation(
            "User deletion started. UserId={UserId} TraceId={TraceId}",
            normalizedUserId,
            traceId);

        // -------------------------------------------------------
        // FIND USER
        // -------------------------------------------------------

        ApplicationUser? user =
            await _userManager.FindByIdAsync(
                normalizedUserId);

        if (user is null)
        {
            _logger.LogWarning(
                "User deletion failed because user was not found. UserId={UserId} TraceId={TraceId}",
                normalizedUserId,
                traceId);

            return ApiResponse<DeleteUserResponse>
                .CreateFailure(
                    StatusCodes.Status404NotFound,
                    "The selected user could not be found.",
                    ErrorCodes.Users.NotFound,
                    traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();

        // -------------------------------------------------------
        // DELETE USER
        // -------------------------------------------------------

        IdentityResult result =
            await _userManager.DeleteAsync(user);

        if (!result.Succeeded)
        {
            string[] errorCodes =
                result.Errors
                    .Select(error => error.Code)
                    .ToArray();

            _logger.LogError(
                "User deletion failed. UserId={UserId} ErrorCodes={ErrorCodes} TraceId={TraceId}",
                user.Id,
                errorCodes,
                traceId);

            
            return ApiResponse<DeleteUserResponse>
                .CreateFailure(
                    StatusCodes.Status400BadRequest,
                    "The user account could not be deleted. Please try again.",
                    ErrorCodes.Users.DeleteFailed,
                    traceId,
                    result.Errors
                        .Select(error => error.Description)
                        .ToList());
        }

        DateTimeOffset deletedAtUtc =
            DateTimeOffset.UtcNow;

        // -------------------------------------------------------
        // SUCCESS LOG
        // -------------------------------------------------------

        _logger.LogInformation(
            "User deleted successfully. UserId={UserId} TraceId={TraceId}",
            user.Id,
            traceId);

        // -------------------------------------------------------
        // RESPONSE
        // -------------------------------------------------------

        return ApiResponse<DeleteUserResponse>
            .CreateSuccess(
                StatusCodes.Status200OK,
                "The user account was deleted successfully.",
                new DeleteUserResponse
                {
                    UserId = user.Id,
                    DeletedAtUtc = deletedAtUtc
                },
                traceId);
    }

}
