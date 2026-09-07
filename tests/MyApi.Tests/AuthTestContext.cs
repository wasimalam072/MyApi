using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using TestOptions = Microsoft.Extensions.Options.Options;
using MyApi.Common.Constants;
using MyApi.Configuration;
using MyApi.Features.Auth;
using MyApi.Features.Permissions;
using MyApi.Infrastructure.Authentication;
using MyApi.Models.Auth;

namespace MyApi.Tests;

internal sealed class AuthTestContext : IDisposable
{
    public TestUserManager Users { get; } = new();
    public TestRoleManager Roles { get; } = new();
    public TestSignInManager SignIn { get; }
    public PermissionService Permissions { get; }
    public AuthService Service { get; }
    public JwtSettings Jwt { get; } = new()
    {
        Key = "unit-test-signing-key-with-at-least-32-characters",
        Issuer = "MyApi.Tests", Audience = "MyApi.Tests", ExpirationMinutes = 15
    };

    public AuthTestContext()
    {
        SignIn = new TestSignInManager(Users);
        Permissions = new PermissionService(Users, Roles, NullLogger<PermissionService>.Instance);
        Service = new AuthService(Users, SignIn, Roles,
            new TokenService(TestOptions.Create(Jwt)), Permissions, NullLogger<AuthService>.Instance);
    }

    public void Dispose()
    {
        Users.Dispose();
        Roles.Dispose();
    }
}

internal sealed class TestUserManager : UserManager<ApplicationUser>
{
    public ApplicationUser? User { get; set; }
    public ApplicationUser? CreatedUser { get; private set; }
    public ApplicationUser? DeletedUser { get; private set; }
    public string? SearchedEmail { get; private set; }
    public string? AssignedRole { get; private set; }
    public bool LockedOut { get; set; }
    public IdentityResult CreationResult { get; set; } = IdentityResult.Success;
    public IdentityResult RoleResult { get; set; } = IdentityResult.Success;
    public IList<string> RoleNames { get; set; } = [ApplicationRoles.User];
    public IList<Claim> Claims { get; set; } = [];
    public int RoleQueries { get; private set; }
    public int ClaimQueries { get; private set; }

    public TestUserManager() : base(
        new UnusedUserStore(), TestOptions.Create(new IdentityOptions()), new PasswordHasher<ApplicationUser>(),
        [], [], new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
        NullLogger<UserManager<ApplicationUser>>.Instance)
    {
    }

    public override Task<ApplicationUser?> FindByEmailAsync(string email)
    {
        SearchedEmail = email;
        return Task.FromResult(User);
    }

    public override Task<IdentityResult> CreateAsync(ApplicationUser user, string password)
    {
        CreatedUser = user;
        return Task.FromResult(CreationResult);
    }

    public override Task<IdentityResult> AddToRoleAsync(ApplicationUser user, string role)
    {
        AssignedRole = role;
        return Task.FromResult(RoleResult);
    }

    public override Task<IdentityResult> DeleteAsync(ApplicationUser user)
    {
        DeletedUser = user;
        return Task.FromResult(IdentityResult.Success);
    }

    public override Task<bool> IsLockedOutAsync(ApplicationUser user) => Task.FromResult(LockedOut);

    public override Task<IList<string>> GetRolesAsync(ApplicationUser user)
    {
        RoleQueries++;
        return Task.FromResult(RoleNames);
    }

    public override Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
    {
        ClaimQueries++;
        return Task.FromResult(Claims);
    }

    // Fail immediately if a test unexpectedly reaches persistence. Tests control
    // Identity outcomes through the manager overrides above.
    private sealed class UnusedUserStore : IUserStore<ApplicationUser>
    {
        public void Dispose() { }
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}

internal sealed class TestRoleManager : RoleManager<IdentityRole>
{
    public bool DefaultRoleExists { get; set; } = true;
    public Dictionary<string, IdentityRole> RolesByName { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, IList<Claim>> Claims { get; } = new();
    public int RoleQueries { get; private set; }
    public int ClaimQueries { get; private set; }

    public TestRoleManager() : base(new UnusedRoleStore(), [], new UpperInvariantLookupNormalizer(),
        new IdentityErrorDescriber(), NullLogger<RoleManager<IdentityRole>>.Instance)
    {
        var role = new IdentityRole(ApplicationRoles.User);
        RolesByName.Add(ApplicationRoles.User, role);
        Claims.Add(role.Id, []);
    }

    public override Task<bool> RoleExistsAsync(string roleName) => Task.FromResult(DefaultRoleExists);

    public override Task<IdentityRole?> FindByNameAsync(string roleName)
    {
        RoleQueries++;
        return Task.FromResult(RolesByName.GetValueOrDefault(roleName));
    }

    public override Task<IList<Claim>> GetClaimsAsync(IdentityRole role)
    {
        ClaimQueries++;
        return Task.FromResult(Claims[role.Id]);
    }

    private sealed class UnusedRoleStore : IRoleStore<IdentityRole>
    {
        public void Dispose() { }
        public Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IdentityRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}

internal sealed class TestSignInManager : SignInManager<ApplicationUser>
{
    public SignInResult Result { get; set; } = SignInResult.Success;
    public int Checks { get; private set; }
    public bool LockoutOnFailure { get; private set; }

    public TestSignInManager(UserManager<ApplicationUser> users) : base(
        users, new HttpContextAccessor(), new UserClaimsPrincipalFactory<ApplicationUser>(users, TestOptions.Create(new IdentityOptions())),
        TestOptions.Create(new IdentityOptions()), NullLogger<SignInManager<ApplicationUser>>.Instance,
        new AuthenticationSchemeProvider(TestOptions.Create(new AuthenticationOptions())), new DefaultUserConfirmation<ApplicationUser>())
    {
    }

    public override Task<SignInResult> CheckPasswordSignInAsync(ApplicationUser user, string password, bool lockoutOnFailure)
    {
        Checks++;
        LockoutOnFailure = lockoutOnFailure;
        return Task.FromResult(Result);
    }
}
