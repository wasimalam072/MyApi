namespace MyApi.Features.Auth;

/// <summary>
/// Handles application authentication operations such as
/// user registration and login.
///
/// This service works with ASP.NET Core Identity for:
/// - User creation
/// - Password validation
/// - Account lockout
/// - Role assignment
/// - User claims
/// - JWT access-token generation
/// </summary>
public sealed class AuthService : IAuthService
{
    private const string DefaultRole = ApplicationRoles.User;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ITokenService _tokenService;
private readonly IPermissionService _permissionService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, ITokenService tokenService, IPermissionService permissionService, ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _tokenService = tokenService;
        _permissionService = permissionService;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new application user and assigns
    /// the application's default User role.
    /// </summary>
    public async Task<ApiResponse<RegisterResponse>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string traceId = CreateTraceId();

        string email = NormalizeEmail(request.Email);
        string phoneNumber = NormalizePhoneNumber(request.PhoneNumber);

        _logger.LogInformation(
            "User registration started. TraceId={TraceId}",
            traceId);

        // -------------------------------------------------------
        // CHECK DEFAULT ROLE CONFIGURATION
        // -------------------------------------------------------
        bool defaultRoleExists = await _roleManager.RoleExistsAsync(DefaultRole);

        if (!defaultRoleExists)
        {
            _logger.LogError(
                "User registration failed because default role {Role} does not exist. TraceId={TraceId}",
                DefaultRole,
                traceId);

            return CreateRegisterFailure(
                StatusCodes.Status500InternalServerError,
                "Registration is temporarily unavailable. Please try again later.",
                "AUTH_CONFIGURATION_ERROR",
                traceId);
        }

        // Check for an existing account before creating a new user.
        // Never log the actual email address because authentication
        // information should not unnecessarily appear in application logs.

        ApplicationUser? existingUser = await _userManager.FindByEmailAsync(email);

        if (existingUser is not null)
        {
            // Do NOT log the actual email.
            _logger.LogWarning(
                "User registration rejected because email already exists. TraceId={TraceId}",
                traceId);

            return CreateRegisterFailure(
                StatusCodes.Status409Conflict,
                "An account already exists with the provided email address.",
                "AUTH_ACCOUNT_EXISTS",
                traceId);
        }

        // // -------------------------------------------------------
        // // CHECK PHONE NUMBER
        // // -------------------------------------------------------
        // bool phoneNumberExists = await _userManager.Users.AsNoTracking().AnyAsync(user => user.PhoneNumber == phoneNumber, cancellationToken);

        // if (phoneNumberExists)
        // {
        //     // Do NOT log the actual phone number.
        //     _logger.LogWarning(
        //         "User registration rejected because phone number already exists. TraceId={TraceId}",
        //         traceId);


        //                     return ApiResponse<RegisterResponse>
        //                     .CreateFailure(
        //                         StatusCodes.Status409Conflict,
        //                         "This phone number is already associated with another account.",
        //                         ErrorCodes.Users.PhoneNumberAlreadyExists,
        //                         traceId);
        // }

        // -------------------------------------------------------
        // CREATE USER
        // -------------------------------------------------------
        var user = new ApplicationUser
        {
            FullName = request.FullName.Trim(),
            Email = email,
            UserName = email,
            PhoneNumber = phoneNumber,

            // New contact information must be verified
            // through the confirmation workflow.
            EmailConfirmed = false,
            PhoneNumberConfirmed = false
        };

        IdentityResult createResult = await _userManager.CreateAsync(user, request.Password);

        if (!createResult.Succeeded)
        {
            string[] errorCodes =
            createResult.Errors
                .Select(error => error.Code)
                .ToArray();

            _logger.LogWarning(
                "User registration failed during Identity user creation. ErrorCodes={ErrorCodes} TraceId={TraceId}",
                errorCodes,
                traceId);

            return CreateRegisterFailure(
                StatusCodes.Status400BadRequest,
                "Registration could not be completed. Please check the information provided.",
                "AUTH_REGISTRATION_FAILED",
                traceId,
                createResult.Errors
                    .Select(error => error.Description)
                    .ToList());
        }

        // Every newly registered account receives only the standard
        // User role. Administrative permissions should be assigned
        // separately through role/permission management.

        IdentityResult roleResult = await _userManager.AddToRoleAsync(user, DefaultRole);

        if (!roleResult.Succeeded)
        {
            string[] roleErrors =
            roleResult.Errors
                .Select(error => error.Code)
                .ToArray();

            _logger.LogError(
                "Role assignment failed for UserId={UserId}. Role={Role}. Errors={Errors}. TraceId={TraceId}",
                user.Id,
                DefaultRole,
                roleErrors,
                traceId);

            await RollbackRegistrationAsync(
                user,
                traceId);

            return CreateRegisterFailure(
                StatusCodes.Status500InternalServerError,
                "Your account could not be completed. Please try again later.",
                "AUTH_ROLE_ASSIGNMENT_FAILED",
                traceId);
        }

        // -------------------------------------------------------
        // GET ROLES
        // -------------------------------------------------------

        IList<string> roles =
            await _userManager.GetRolesAsync(user);

        // -------------------------------------------------------
        // MAP RESPONSE
        // -------------------------------------------------------

        RegisterResponse registerResponse =
                    await MapToRegisterResponseAsync(
                        user,
                        roles,
                        cancellationToken);

        // -------------------------------------------------------
        // SUCCESS LOG
        // -------------------------------------------------------

        _logger.LogInformation(
            "User registration completed successfully. UserId={UserId} Role={Role} TraceId={TraceId}",
            user.Id,
            DefaultRole,
            traceId);

        return new ApiResponse<RegisterResponse>
        {
            StatusCode = StatusCodes.Status201Created,
            Message = "Registration successful. Your account has been created.",
            Data = registerResponse,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Authenticates a user using email and password and,
    /// when successful, creates a JWT access token.
    /// </summary>
    public async Task<ApiResponse<LoginResponse>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string traceId = CreateTraceId();

        string email = NormalizeEmail(request.Email);

        _logger.LogInformation(
            "User login attempt started. TraceId={TraceId}",
            traceId);

        // -------------------------------------------------------
        // FIND USER
        // -------------------------------------------------------

        ApplicationUser? user = await _userManager.FindByEmailAsync(email);

        // Always return the same invalid-credentials response when
        // the account does not exist. This avoids revealing whether
        // a particular email address is registered.

        if (user is null)
        {
            _logger.LogWarning(
                "Login failed because credentials were invalid. TraceId={TraceId}",
                traceId);

            return InvalidLoginResponse(traceId);
        }

        // Checking the current lockout state before password
        // validation lets us return the correct account status.

        bool isLockedOut =
            await _userManager.IsLockedOutAsync(user);

        if (isLockedOut)
        {
            DateTimeOffset? lockoutEnd =
                await _userManager.GetLockoutEndDateAsync(user);

            _logger.LogWarning(
                "Login rejected because account is locked. UserId={UserId} LockoutEnd={LockoutEnd} TraceId={TraceId}",
                user.Id,
                lockoutEnd,
                traceId);

            return AccountLockedResponse(
                traceId);
        }

        /*
         * CheckPasswordSignInAsync:
         *
         * - Validates the password.
         * - Applies ASP.NET Core Identity sign-in requirements.
         * - Increments failed-access count when lockoutOnFailure is true.
         * - Can return LockedOut or NotAllowed.
         */

        SignInResult signInResult =
            await _signInManager.CheckPasswordSignInAsync(
                user,
                request.Password,
                lockoutOnFailure: true);

        if (signInResult.IsLockedOut)
        {
            DateTimeOffset? lockoutEnd =
                await _userManager.GetLockoutEndDateAsync(user);

            _logger.LogWarning(
                "Account locked after repeated failed login attempts. UserId={UserId} LockoutEnd={LockoutEnd} TraceId={TraceId}",
                user.Id,
                lockoutEnd,
                traceId);

            return AccountLockedResponse(
                traceId);
        }

        // /*
        //  * Identity returns NotAllowed when sign-in requirements
        //  * are not satisfied.
        //  *
        //  * Examples:
        //  * - RequireConfirmedEmail = true but EmailConfirmed = false
        //  * - RequireConfirmedPhoneNumber = true but
        //  *   PhoneNumberConfirmed = false
        //  */
        // if (signInResult.IsNotAllowed)
        // {
        //     _logger.LogWarning(
        //         "Login rejected because account verification requirements are not satisfied. UserId={UserId} TraceId={TraceId}",
        //         user.Id,
        //         traceId);

        //     return ApiResponse<LoginResponse>
        //         .CreateFailure(
        //             StatusCodes.Status403Forbidden,
        //             "Your email address has not been verified. Please verify your email before signing in.",
        //             ErrorCodes.Users.UpdateFailed,
        //             traceId,
        //             null);
        // }

        // -------------------------------------------------------
        // PASSWORD INVALID
        // -------------------------------------------------------

        if (!signInResult.Succeeded)
        {
            _logger.LogWarning(
                "Login failed because credentials were invalid. UserId={UserId} FailedAttempts={FailedAttempts} TraceId={TraceId}",
                user.Id,
                traceId);

            return InvalidLoginResponse(
                traceId);
        }

        // // -------------------------------------------------------
        // // CHECK EMAIL CONFIRMATION
        // // -------------------------------------------------------

        // if (!user.EmailConfirmed)
        // {
        //     _logger.LogWarning(
        //         "Login rejected because email is not confirmed. UserId={UserId} TraceId={TraceId}",
        //         user.Id,
        //         traceId);

        //                     return ApiResponse<LoginResponse>
        //         .CreateFailure(
        //             StatusCodes.Status403Forbidden,
        //             "Your email address has not been verified. Please verify your email before signing in.",
        //             ErrorCodes.Users.UpdateFailed,
        //             traceId,
        //             null);
        // }

        // // -------------------------------------------------------
        // // CHECK PHONE CONFIRMATION
        // // -------------------------------------------------------

        // if (!user.PhoneNumberConfirmed)
        // {
        //     _logger.LogWarning(
        //         "Login rejected because phone number is not confirmed. UserId={UserId} TraceId={TraceId}",
        //         user.Id,
        //         traceId);

        //                     return ApiResponse<LoginResponse>
        //         .CreateFailure(
        //             StatusCodes.Status403Forbidden,
        //             "Your phone number has not been verified. Please verify your phone number before signing in.",
        //             ErrorCodes.Users.UpdateFailed,
        //             traceId,
        //             null);
        // }

        cancellationToken.ThrowIfCancellationRequested();

        // -------------------------------------------------------
        // GET ROLES
        // -------------------------------------------------------

        IList<string> roles =
           await _userManager.GetRolesAsync(user);

        // -------------------------------------------------------
        // GET PERMISSIONS
        // -------------------------------------------------------

IReadOnlyList<string> permissions =
    await _permissionService
        .GetEffectivePermissionsAsync(
            user,
            cancellationToken);

        // -------------------------------------------------------
        // CREATE TOKEN
        // -------------------------------------------------------

        TokenResult tokenResult = await _tokenService.CreateAccessTokenAsync(user, cancellationToken);

        // -------------------------------------------------------
        // MAP RESPONSE
        // -------------------------------------------------------

        LoginResponse loginResponse =
            MapToLoginResponse(
                user,
                tokenResult,
                roles,
                permissions);

        // -------------------------------------------------------
        // SUCCESS LOG
        // -------------------------------------------------------

        _logger.LogInformation(
            "User login completed successfully. UserId={UserId} TraceId={TraceId}",
            user.Id,
            traceId);

        return new ApiResponse<LoginResponse>
        {
            StatusCode = StatusCodes.Status200OK,
            Message = "Login successful.",
            Data = loginResponse,
            TraceId = traceId
        };
    }

// ============================================================
    // REGISTRATION HELPERS
    // ============================================================

    /// <summary>
    /// Removes a newly created account when registration cannot
    /// finish successfully.
    ///
    /// This prevents partially configured Identity users from
    /// remaining in the database.
    /// </summary>
    private async Task RollbackRegistrationAsync(
        ApplicationUser user,
        string traceId)
    {
        IdentityResult deleteResult =
            await _userManager.DeleteAsync(user);

        if (deleteResult.Succeeded)
        {
            _logger.LogInformation(
                "Registration rollback completed. UserId={UserId} TraceId={TraceId}",
                user.Id,
                traceId);

            return;
        }

        _logger.LogCritical(
            "Registration rollback failed. UserId={UserId} ErrorCodes={ErrorCodes} TraceId={TraceId}",
            user.Id,
            deleteResult.Errors
                .Select(error => error.Code)
                .ToArray(),
            traceId);
    }

    /// <summary>
    /// Converts an Identity user into the response returned after
    /// successful registration.
    /// </summary>
    private async Task<RegisterResponse> MapToRegisterResponseAsync(
        ApplicationUser user,
        IEnumerable<string> roles,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

    IReadOnlyList<string> permissions =
        await _permissionService
            .GetEffectivePermissionsAsync(
                user,
                cancellationToken);

        return new RegisterResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber,

            EmailConfirmed =
                user.EmailConfirmed,

            PhoneNumberConfirmed =
                user.PhoneNumberConfirmed,

            Roles =
                NormalizeRoles(roles),

            Permissions =
                permissions
        };
    }


    // ============================================================
    // LOGIN HELPERS
    // ============================================================

    /// <summary>
    /// Creates the successful login response returned to the client.
    /// </summary>
    private static LoginResponse MapToLoginResponse(
        ApplicationUser user,
        TokenResult tokenResult,
        IEnumerable<string> roles,
        IReadOnlyList<string> permissions)
    {
        return new LoginResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber,

            EmailConfirmed =
                user.EmailConfirmed,

            PhoneNumberConfirmed =
                user.PhoneNumberConfirmed,

            AccessToken =
                tokenResult.AccessToken,

            AccessTokenExpiresAtUtc =
                tokenResult.ExpiresAtUtc,

            Roles =
                NormalizeRoles(roles),

            Permissions =
                permissions
        };
    }

/// <summary>
    /// Returns a generic authentication failure response.
    ///
    /// The response intentionally does not indicate whether
    /// the email or password was incorrect.
    /// </summary>
    private static ApiResponse<LoginResponse>
        InvalidLoginResponse(
            string traceId)
    {
        return new ApiResponse<LoginResponse>
        {
            StatusCode =
                StatusCodes.Status401Unauthorized,

            Message =
                "The email or password you entered is incorrect.",

            ErrorCode =
                "AUTH_INVALID_CREDENTIALS",

            TraceId =
                traceId
        };
    }

    /// <summary>
    /// Creates the response returned when Identity has temporarily
    /// locked an account after repeated failed login attempts.
    /// </summary>
    private static ApiResponse<LoginResponse>
        AccountLockedResponse(
            string traceId)
    {
        return new ApiResponse<LoginResponse>
        {
            StatusCode =
                StatusCodes.Status423Locked,

            Message =
                "Your account has been temporarily locked after multiple failed sign-in attempts. Please try again later.",

            ErrorCode =
                "AUTH_ACCOUNT_LOCKED",

            TraceId =
                traceId
        };
    }


/// <summary>
    /// Removes duplicate role names and returns them
    /// in a predictable order.
    /// </summary>
    private static IReadOnlyList<string> NormalizeRoles(
        IEnumerable<string> roles)
    {
        return roles
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .OrderBy(
                role =>
                    role)
            .ToList();
    }

    /// <summary>
    /// Normalizes email input before it is passed to Identity.
    /// ASP.NET Core Identity performs its own normalized-email
    /// handling as well; this keeps stored application values tidy.
    /// </summary>
    private static string NormalizeEmail(
        string email)
    {
        return email
            .Trim()
            .ToLowerInvariant();
    }

    /// <summary>
    /// Removes surrounding whitespace from a phone number.
    ///
    /// More advanced phone-number normalization can be added later
    /// if the application requires a single international format.
    /// </summary>
    private static string NormalizePhoneNumber(
        string phoneNumber)
    {
        return phoneNumber.Trim();
    }

    /// <summary>
    /// Uses the current request Activity identifier whenever
    /// available so logs and API responses can be correlated.
    /// </summary>
    private static string CreateTraceId()
    {
        return Activity.Current?.Id
               ?? Guid.NewGuid().ToString();
    }

    /// <summary>
    /// Creates a consistent registration failure response.
    /// </summary>
    private static ApiResponse<RegisterResponse>
        CreateRegisterFailure(
            int statusCode,
            string message,
            string errorCode,
            string traceId,
            IReadOnlyList<string>? errors = null)
    {
        return new ApiResponse<RegisterResponse>
        {
            StatusCode = statusCode,
            Message = message,
            ErrorCode = errorCode,
            Errors = errors,
            TraceId = traceId
        };
    }
}