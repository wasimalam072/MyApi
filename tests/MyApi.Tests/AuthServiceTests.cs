using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using MyApi.Common.Constants;
using MyApi.Models.Auth;

namespace MyApi.Tests;

public sealed class AuthServiceTests
{
    [Fact]
    public async Task Registration_normalizes_contact_details_and_assigns_only_the_default_role()
    {
        using var context = new AuthTestContext();
        var response = await context.Service.RegisterAsync(Registration());

        Assert.Equal(201, response.StatusCode);
        Assert.True(response.Success);
        Assert.Equal("Test User", response.Data!.FullName);
        Assert.Equal("test@example.com", response.Data.Email);
        Assert.Equal("+15555550100", response.Data.PhoneNumber);
        Assert.False(response.Data.EmailConfirmed);
        Assert.False(response.Data.PhoneNumberConfirmed);
        Assert.Equal(ApplicationRoles.User, context.Users.AssignedRole);
        Assert.Equal(new[] { ApplicationRoles.User }, response.Data.Roles);
        Assert.Equal(context.Users.CreatedUser!.Email, context.Users.CreatedUser.UserName);
        Assert.Null(context.Users.DeletedUser);
    }

    [Fact]
    public async Task Existing_email_returns_conflict_without_creating_another_user()
    {
        using var context = new AuthTestContext();
        context.Users.User = User();
        var response = await context.Service.RegisterAsync(Registration());

        Assert.Equal(409, response.StatusCode);
        Assert.Equal(ErrorCodes.Authentication.AccountExists, response.ErrorCode);
        Assert.Null(context.Users.CreatedUser);
    }

    [Fact]
    public async Task Missing_default_role_prevents_account_creation()
    {
        using var context = new AuthTestContext();
        context.Roles.DefaultRoleExists = false;
        var response = await context.Service.RegisterAsync(Registration());

        Assert.Equal(500, response.StatusCode);
        Assert.Equal(ErrorCodes.Authentication.ConfigurationError, response.ErrorCode);
        Assert.Null(context.Users.CreatedUser);
    }

    [Fact]
    public async Task Failed_user_creation_returns_validation_details_without_assigning_roles()
    {
        using var context = new AuthTestContext();
        context.Users.CreationResult = IdentityResult.Failed(new IdentityError
        {
            Code = "PasswordTooShort", Description = "Password is too short."
        });
        var response = await context.Service.RegisterAsync(Registration());

        Assert.Equal(400, response.StatusCode);
        Assert.Equal(ErrorCodes.Authentication.RegistrationFailed, response.ErrorCode);
        Assert.Contains("Password is too short.", response.Errors!);
        Assert.Null(context.Users.AssignedRole);
    }

    [Fact]
    public async Task Failed_role_assignment_deletes_the_newly_created_account()
    {
        using var context = new AuthTestContext();
        context.Users.RoleResult = IdentityResult.Failed(new IdentityError { Code = "RoleFailure" });
        var response = await context.Service.RegisterAsync(Registration());

        Assert.Equal(500, response.StatusCode);
        Assert.Equal(ErrorCodes.Authentication.RoleAssignmentFailed, response.ErrorCode);
        Assert.Same(context.Users.CreatedUser, context.Users.DeletedUser);
        Assert.Equal(0, context.Users.RoleQueries);
    }

    [Fact]
    public async Task Unknown_accounts_and_invalid_passwords_return_the_same_public_error()
    {
        using var context = new AuthTestContext();
        var missing = await context.Service.LoginAsync(Login());
        context.Users.User = User();
        context.SignIn.Result = SignInResult.Failed;
        var invalid = await context.Service.LoginAsync(Login());

        Assert.Equal(401, invalid.StatusCode);
        Assert.Equal(missing.StatusCode, invalid.StatusCode);
        Assert.Equal(missing.Message, invalid.Message);
        Assert.Equal(missing.ErrorCode, invalid.ErrorCode);
        Assert.Null(invalid.Data);
        Assert.True(context.SignIn.LockoutOnFailure);
        Assert.Equal(0, context.Users.RoleQueries);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Existing_and_new_lockouts_return_423_without_a_token(bool alreadyLocked)
    {
        using var context = new AuthTestContext();
        context.Users.User = User();
        context.Users.LockedOut = alreadyLocked;
        context.SignIn.Result = SignInResult.LockedOut;
        var response = await context.Service.LoginAsync(Login());

        Assert.Equal(423, response.StatusCode);
        Assert.Equal(ErrorCodes.Authentication.AccountLocked, response.ErrorCode);
        Assert.Null(response.Data);
        Assert.Equal(alreadyLocked ? 0 : 1, context.SignIn.Checks);
    }

    [Fact]
    public async Task Unmet_sign_in_requirements_do_not_issue_a_token()
    {
        using var context = new AuthTestContext();
        context.Users.User = User();
        context.SignIn.Result = SignInResult.NotAllowed;
        var response = await context.Service.LoginAsync(Login());

        Assert.Equal(401, response.StatusCode);
        Assert.Null(response.Data);
        Assert.Equal(0, context.Users.RoleQueries);
    }

    [Fact]
    public async Task Login_issues_a_valid_token_with_the_same_roles_and_permissions_as_the_response()
    {
        using var context = new AuthTestContext();
        context.Users.User = User();
        context.Users.RoleNames = [ApplicationRoles.User, ApplicationRoles.User.ToLowerInvariant()];
        context.Users.Claims = [new Claim(CustomClaimTypes.Permission, "Test.Write")];
        context.Roles.Claims[context.Roles.RolesByName[ApplicationRoles.User].Id] = [new Claim(CustomClaimTypes.Permission, "Test.Read")];

        var response = await context.Service.LoginAsync(Login());
        Assert.Equal(200, response.StatusCode);
        Assert.Equal("test@example.com", context.Users.SearchedEmail);
        Assert.Equal(new[] { ApplicationRoles.User }, response.Data!.Roles);
        Assert.Equal(new[] { "Test.Read", "Test.Write" }, response.Data.Permissions);

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        ClaimsPrincipal principal = handler.ValidateToken(response.Data.AccessToken, new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = context.Jwt.Issuer,
            ValidateAudience = true, ValidAudience = context.Jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(context.Jwt.Key)),
            ValidateLifetime = true, ClockSkew = TimeSpan.Zero
        }, out var token);

        Assert.Equal(context.Users.User.Id, principal.FindFirst(JwtRegisteredClaimNames.Sub)!.Value);
        Assert.Equal(response.Data.Roles, principal.FindAll(ClaimTypes.Role).Select(claim => claim.Value));
        Assert.Equal(response.Data.Permissions, principal.FindAll(CustomClaimTypes.Permission).Select(claim => claim.Value));
        Assert.Equal(context.Jwt.ExpirationMinutes, (token.ValidTo - token.ValidFrom).TotalMinutes);
        Assert.InRange((response.Data.AccessTokenExpiresAtUtc - token.ValidTo).TotalSeconds, 0, 1);
        Assert.Equal(1, context.Users.RoleQueries);
        Assert.Equal(1, context.Users.ClaimQueries);
        Assert.Equal(1, context.Roles.ClaimQueries);
    }

    [Fact]
    public async Task Cancelled_requests_stop_before_identity_operations()
    {
        using var context = new AuthTestContext();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Service.LoginAsync(Login(), cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Service.RegisterAsync(Registration(), cancellation.Token));
        Assert.Null(context.Users.SearchedEmail);
        Assert.Null(context.Users.CreatedUser);
    }

    internal static ApplicationUser User() => new()
    {
        Id = "test-user", Email = "test@example.com", UserName = "test@example.com", FullName = "Test User"
    };

    private static LoginRequest Login() => new() { Email = " TEST@EXAMPLE.COM ", Password = "Password123!" };

    private static RegisterRequest Registration() => new()
    {
        FullName = " Test User ", Email = " TEST@EXAMPLE.COM ", PhoneNumber = " +15555550100 ",
        Password = "Password123!", ConfirmPassword = "Password123!"
    };
}
