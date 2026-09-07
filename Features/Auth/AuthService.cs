namespace MyApi.Features.Auth;

/// <summary>
/// Registers users and authenticates passwords using ASP.NET Core Identity.
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

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        ITokenService tokenService,
        IPermissionService permissionService,
        ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _tokenService = tokenService;
        _permissionService = permissionService;
        _logger = logger;
    }

    public async Task<ApiResponse<RegisterResponse>> RegisterAsync(
        RegisterRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string traceId = CreateTraceId();
        string email = NormalizeEmail(request.Email);

        if (!await _roleManager.RoleExistsAsync(DefaultRole))
        {
            _logger.LogError(
                "Registration requires role {Role}. TraceId={TraceId}", DefaultRole, traceId);

            return ApiResponse<RegisterResponse>.CreateFailure(
                StatusCodes.Status500InternalServerError,
                "Registration is temporarily unavailable. Please try again later.",
                ErrorCodes.Authentication.ConfigurationError,
                traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (await _userManager.FindByEmailAsync(email) is not null)
        {
            _logger.LogWarning("Registration rejected because the account exists. TraceId={TraceId}", traceId);

            return ApiResponse<RegisterResponse>.CreateFailure(
                StatusCodes.Status409Conflict,
                "An account already exists with the provided email address.",
                ErrorCodes.Authentication.AccountExists,
                traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var user = new ApplicationUser
        {
            FullName = request.FullName.Trim(),
            Email = email,
            UserName = email,
            PhoneNumber = request.PhoneNumber.Trim(),
            EmailConfirmed = false,
            PhoneNumberConfirmed = false
        };

        IdentityResult createResult = await _userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            _logger.LogWarning(
                "Identity rejected registration. ErrorCodes={ErrorCodes} TraceId={TraceId}",
                createResult.Errors.Select(error => error.Code).ToArray(), traceId);

            return ApiResponse<RegisterResponse>.CreateFailure(
                StatusCodes.Status400BadRequest,
                "Registration could not be completed. Please check the information provided.",
                ErrorCodes.Authentication.RegistrationFailed,
                traceId,
                createResult.Errors.Select(error => error.Description).ToArray());
        }

        // Complete or undo role assignment before observing request cancellation.
        IdentityResult roleResult = await _userManager.AddToRoleAsync(user, DefaultRole);
        if (!roleResult.Succeeded)
        {
            _logger.LogError(
                "Role assignment failed. UserId={UserId} Role={Role} ErrorCodes={ErrorCodes} TraceId={TraceId}",
                user.Id, DefaultRole, roleResult.Errors.Select(error => error.Code).ToArray(), traceId);

            await RollbackRegistrationAsync(user, traceId);

            return ApiResponse<RegisterResponse>.CreateFailure(
                StatusCodes.Status500InternalServerError,
                "Your account could not be completed. Please try again later.",
                ErrorCodes.Authentication.RoleAssignmentFailed,
                traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<string> roles = NormalizeRoles(await _userManager.GetRolesAsync(user));
        IReadOnlyList<string> permissions = await _permissionService.GetEffectivePermissionsAsync(
            user, roles, cancellationToken);

        var response = new RegisterResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            Roles = roles,
            Permissions = permissions
        };

        _logger.LogInformation("Registration completed. UserId={UserId} TraceId={TraceId}", user.Id, traceId);

        return ApiResponse<RegisterResponse>.CreateSuccess(
            StatusCodes.Status201Created,
            "Registration successful. Your account has been created.",
            response,
            traceId);
    }

    public async Task<ApiResponse<LoginResponse>> LoginAsync(
        LoginRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string traceId = CreateTraceId();
        ApplicationUser? user = await _userManager.FindByEmailAsync(NormalizeEmail(request.Email));
        if (user is null)
        {
            _logger.LogWarning("Login rejected because credentials were invalid. TraceId={TraceId}", traceId);
            return InvalidLoginResponse(traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (await _userManager.IsLockedOutAsync(user))
        {
            return AccountLockedResponse(user, traceId);
        }

        // Identity enforces sign-in requirements and records failed password attempts.
        SignInResult signInResult = await _signInManager.CheckPasswordSignInAsync(
            user, request.Password, lockoutOnFailure: true);

        if (signInResult.IsLockedOut)
        {
            return AccountLockedResponse(user, traceId);
        }

        if (!signInResult.Succeeded)
        {
            _logger.LogWarning("Login rejected. UserId={UserId} TraceId={TraceId}", user.Id, traceId);
            return InvalidLoginResponse(traceId);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // Identity services share a scoped DbContext, so await queries sequentially.
        IReadOnlyList<string> roles = NormalizeRoles(await _userManager.GetRolesAsync(user));
        IReadOnlyList<string> permissions = await _permissionService.GetEffectivePermissionsAsync(
            user, roles, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        TokenResult token = _tokenService.CreateAccessToken(user, roles, permissions);
        var response = new LoginResponse
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            PhoneNumber = user.PhoneNumber,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            AccessToken = token.AccessToken,
            AccessTokenExpiresAtUtc = token.ExpiresAtUtc,
            Roles = roles,
            Permissions = permissions
        };

        _logger.LogInformation("Login completed. UserId={UserId} TraceId={TraceId}", user.Id, traceId);

        return ApiResponse<LoginResponse>.CreateSuccess(
            StatusCodes.Status200OK, "Login successful.", response, traceId);
    }

    private async Task RollbackRegistrationAsync(ApplicationUser user, string traceId)
    {
        IdentityResult result = await _userManager.DeleteAsync(user);
        if (result.Succeeded)
        {
            _logger.LogInformation("Registration rollback completed. UserId={UserId} TraceId={TraceId}", user.Id, traceId);
            return;
        }

        _logger.LogCritical(
            "Registration rollback failed. UserId={UserId} ErrorCodes={ErrorCodes} TraceId={TraceId}",
            user.Id, result.Errors.Select(error => error.Code).ToArray(), traceId);
    }

    private ApiResponse<LoginResponse> AccountLockedResponse(ApplicationUser user, string traceId)
    {
        _logger.LogWarning("Login rejected for locked account. UserId={UserId} TraceId={TraceId}", user.Id, traceId);

        return ApiResponse<LoginResponse>.CreateFailure(
            StatusCodes.Status423Locked,
            "Your account has been temporarily locked after multiple failed sign-in attempts. Please try again later.",
            ErrorCodes.Authentication.AccountLocked,
            traceId);
    }

    private static ApiResponse<LoginResponse> InvalidLoginResponse(string traceId) =>
        ApiResponse<LoginResponse>.CreateFailure(
            StatusCodes.Status401Unauthorized,
            "The email or password you entered is incorrect.",
            ErrorCodes.Authentication.InvalidCredentials,
            traceId);

    private static IReadOnlyList<string> NormalizeRoles(IEnumerable<string> roles) => roles
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(role => role, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static string CreateTraceId() => Activity.Current?.Id ?? Guid.NewGuid().ToString();
}
