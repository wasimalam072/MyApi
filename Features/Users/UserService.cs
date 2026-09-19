namespace MyApi.Features.Users;

/// <summary>
/// Handles profile operations for the currently authenticated user.
/// </summary>
public sealed class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserResponseMapper _userResponseMapper;
    private readonly ILogger<UserService> _logger;

    public UserService(
        UserManager<ApplicationUser> userManager,
        IUserResponseMapper userResponseMapper,
        ILogger<UserService> logger)
    {
        _userManager = userManager;
        _userResponseMapper = userResponseMapper;
        _logger = logger;
    }

    public async Task<ApiResponse<RegisteredUserResponse>> GetCurrentUserAsync(string currentUserId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string traceId = Activity.Current?.Id ?? Guid.NewGuid().ToString();

        // -------------------------------------------------------
        // VALIDATE USER ID
        // -------------------------------------------------------

        if (string.IsNullOrWhiteSpace(currentUserId))
        {
            _logger.LogWarning("Get user by ID rejected because UserId was empty. TraceId={TraceId}", traceId);

            return ApiResponse<RegisteredUserResponse>.CreateFailure(
                StatusCodes.Status401Unauthorized,
                "Your authentication information is invalid. Please sign in again.",
                 ErrorCodes.Authentication.UserIdMissing,
                 traceId);
        }

        // -------------------------------------------------------
        // REQUEST START
        // -------------------------------------------------------

        _logger.LogInformation("Retrieving user by ID. TraceId={TraceId}", traceId);

        // -------------------------------------------------------
        // FIND USER
        // -------------------------------------------------------

        ApplicationUser? user = await _userManager.FindByIdAsync(currentUserId.Trim());

        if (user is null)
        {
            _logger.LogWarning("Requested user was not found. TraceId={TraceId}", traceId);

            return ApiResponse<RegisteredUserResponse>.CreateFailure(
                StatusCodes.Status404NotFound,
                "The requested user could not be found.",
                ErrorCodes.Users.NotFound,
                traceId);
        }

        // -------------------------------------------------------
        // MAP RESPONSE
        // -------------------------------------------------------

        RegisteredUserResponse response = await _userResponseMapper.MapAsync(user, cancellationToken);

        // -------------------------------------------------------
        // SUCCESS LOG
        // -------------------------------------------------------

        _logger.LogInformation("User retrieved successfully. UserId={UserId} TraceId={TraceId}", user.Id, traceId);

        return ApiResponse<RegisteredUserResponse>.CreateSuccess(
                StatusCodes.Status200OK,
                "User retrieved successfully.",
                response,
                traceId);
    }

    public async Task<ApiResponse<RegisteredUserResponse>> UpdateUserAsync(string currentUserId, UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        cancellationToken.ThrowIfCancellationRequested();

        string traceId = Activity.Current?.Id ?? Guid.NewGuid().ToString();

        // -------------------------------------------------------
        // VALIDATE CURRENT USER ID
        // -------------------------------------------------------
        if (string.IsNullOrWhiteSpace(currentUserId))
        {
            _logger.LogWarning("Update user rejected because authenticated UserId was missing. TraceId={TraceId}", traceId);

            return ApiResponse<RegisteredUserResponse>.CreateFailure(
                StatusCodes.Status401Unauthorized,
                "Your authentication information is invalid. Please sign in again.",
                ErrorCodes.Authentication.UserIdMissing,
                traceId);
        }

        // -------------------------------------------------------
        // START LOG
        // -------------------------------------------------------

        _logger.LogInformation("User profile update started. UserId={UserId} TraceId={TraceId}", currentUserId, traceId);

        // -------------------------------------------------------
        // FIND CURRENT USER
        // -------------------------------------------------------

        ApplicationUser? user = await _userManager.FindByIdAsync(currentUserId.Trim());

        if (user is null)
        {
            _logger.LogWarning("User profile update failed because authenticated user was not found. TraceId={TraceId}", traceId);

            return ApiResponse<RegisteredUserResponse>.CreateFailure(
                StatusCodes.Status404NotFound,
                "Your user account could not be found. Please sign in again.",
                ErrorCodes.Users.NotFound,
                traceId);
        }

        // -------------------------------------------------------
        // NORMALIZE VALUES
        // -------------------------------------------------------

        string fullName = request.FullName.Trim();

        string phoneNumber = request.PhoneNumber.Trim();

        // // -------------------------------------------------------
        // // CHECK PHONE NUMBER DUPLICATE
        // // -------------------------------------------------------

        // bool phoneNumberExists =
        //     await _userManager.Users
        //         .AsNoTracking()
        //         .AnyAsync(
        //             existingUser =>
        //                 existingUser.PhoneNumber == phoneNumber
        //                 && existingUser.Id != user.Id,
        //             cancellationToken);

        // if (phoneNumberExists)
        // {
        //     _logger.LogWarning(
        //         "User profile update rejected because phone number is already assigned to another account. UserId={UserId} TraceId={TraceId}",
        //         user.Id,
        //         traceId);

        //                     return ApiResponse<RegisteredUserResponse>
        //                     .CreateFailure(
        //                         StatusCodes.Status409Conflict,
        //                         "This phone number is already associated with another account.",
        //                         ErrorCodes.Users.PhoneNumberAlreadyExists,
        //                         traceId);
        // }

        // -------------------------------------------------------
        // DETECT CHANGES
        // -------------------------------------------------------

        bool fullNameChanged =
            !string.Equals(
                user.FullName,
                fullName,
                StringComparison.Ordinal);

        bool phoneNumberChanged =
            !string.Equals(
                user.PhoneNumber,
                phoneNumber,
                StringComparison.OrdinalIgnoreCase);

        // Avoid unnecessary database updates when the submitted
        // profile already matches the persisted profile.

        if (!fullNameChanged && !phoneNumberChanged)
        {
            RegisteredUserResponse current =
               await _userResponseMapper.MapAsync(
                   user,
                   cancellationToken);

            return ApiResponse<RegisteredUserResponse>
                .CreateSuccess(
                    StatusCodes.Status200OK,
                    "Your profile is already up to date.",
                    current,
                    traceId);
        }

        // -------------------------------------------------------
        // UPDATE ALLOWED FIELDS ONLY
        // -------------------------------------------------------

        user.FullName =
            fullName;

        if (phoneNumberChanged)
        {
            user.PhoneNumber =
                phoneNumber;

            // Ownership of a changed phone number must be
            // verified again before it is considered confirmed.
            user.PhoneNumberConfirmed =
                false;
        }

        // -------------------------------------------------------
        // UPDATE IDENTITY USER
        // -------------------------------------------------------

        IdentityResult result =
            await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
        {
            _logger.LogWarning(
                "User profile update failed. UserId={UserId} ErrorCodes={ErrorCodes} TraceId={TraceId}",
                user.Id,
                result.Errors.Select(x => x.Code),
                traceId);

            return ApiResponse<RegisteredUserResponse>
                .CreateFailure(
                    StatusCodes.Status400BadRequest,
                    "Your profile could not be updated. Please check the information provided.",
                    ErrorCodes.Users.UpdateFailed,
                    traceId,
                    result.Errors
                        .Select(error => error.Description)
                        .ToList());
        }

        RegisteredUserResponse response =
            await _userResponseMapper.MapAsync(
                user,
                cancellationToken);

        _logger.LogInformation(
            "User profile updated. UserId={UserId} FullNameChanged={FullNameChanged} PhoneChanged={PhoneChanged} TraceId={TraceId}",
            user.Id,
            fullNameChanged,
            phoneNumberChanged,
            traceId);

        string message =
            phoneNumberChanged
                ? "Your profile was updated successfully. Please verify your new phone number."
                : "Your profile was updated successfully.";

        return ApiResponse<RegisteredUserResponse>
            .CreateSuccess(
                StatusCodes.Status200OK,
                message,
                response,
                traceId);
    }
}
