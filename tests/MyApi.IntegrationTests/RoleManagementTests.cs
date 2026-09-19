using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using MyApi.Common.Constants;
using MyApi.Models.Auth;
using MyApi.Models.Permissions;
using MyApi.Models.Roles;

namespace MyApi.IntegrationTests;

public sealed class RoleManagementTests
{
    private static string RolesUrl(string userId) => $"/api/v1/roles/GetUserRoles/{userId}";
    private static string UpdateRolesUrl(string userId) => $"/api/v1/roles/UpdateUserRoles/{userId}";

    [Fact]
    public async Task Role_catalog_reports_current_role_permissions_and_ignores_unrelated_claims()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var original = await ApiAssert.Data<List<RoleDefinitionResponse>>(admin.GetAsync("/api/v1/roles"));
        Assert.Equal(Permissions.All.Order(), original.Single(role => role.Name == ApplicationRoles.Admin).Permissions.Order());
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView },
            original.Single(role => role.Name == ApplicationRoles.Manager).Permissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView },
            original.Single(role => role.Name == ApplicationRoles.User).Permissions);

        await using var scope = factory.Services.CreateAsyncScope();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var manager = (await roles.FindByNameAsync(ApplicationRoles.Manager))!;
        foreach (var claim in new[]
        {
            new Claim(CustomClaimTypes.Permission, Permissions.UsersView),
            new Claim(CustomClaimTypes.Permission, Permissions.UsersDelete),
            new Claim(CustomClaimTypes.Permission, Permissions.UsersUpdate),
            new Claim(CustomClaimTypes.Permission, Permissions.UsersView),
            new Claim("Department", "Support")
        })
            Assert.True((await roles.AddClaimAsync(manager, claim)).Succeeded);

        var granted = await ApiAssert.Data<List<RoleDefinitionResponse>>(admin.GetAsync("/api/v1/roles"));
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView },
            granted.Single(role => role.Name == ApplicationRoles.Manager).Permissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView },
            granted.Single(role => role.Name == ApplicationRoles.User).Permissions);

        Assert.True((await roles.RemoveClaimAsync(manager, new Claim(CustomClaimTypes.Permission, Permissions.UsersView))).Succeeded);
        var revoked = await ApiAssert.Data<List<RoleDefinitionResponse>>(admin.GetAsync("/api/v1/roles"));
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate }, revoked.Single(role => role.Name == ApplicationRoles.Manager).Permissions);
    }

    [Fact]
    public async Task Admin_appoints_manager_who_can_remove_and_add_user_role_with_existing_tokens()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var appointed = await factory.RegisterAsync();
        using var manager = await factory.LoginAsync(appointed.Email);
        await ApiAssert.Response<object>(manager.GetAsync("/api/v1/roles"), HttpStatusCode.Forbidden);

        var state = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(appointed.UserId)));
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, state.Permissions);
        var promoted = await SaveAsync(admin, state, " manager ", "MANAGER", " user ");
        Assert.Equal(new[] { ApplicationRoles.Manager, ApplicationRoles.User }, promoted.Roles);
        Assert.NotEqual(state.Version, promoted.Version);
        var catalog = await ApiAssert.Data<List<RoleDefinitionResponse>>(manager.GetAsync("/api/v1/roles"));
        Assert.Equal(ApplicationRoles.All, catalog.Select(role => role.Name));
        var own = await ApiAssert.Data<UserRolesResponse>(manager.GetAsync("/api/v1/roles/GetMyRoles"));
        Assert.Equal(promoted.Roles, own.Roles);

        var registered = await factory.RegisterAsync();
        Assert.Equal(new[] { ApplicationRoles.User }, registered.Roles);
        using var user = await factory.LoginAsync(registered.Email);
        var original = await ApiAssert.Data<UserRolesResponse>(manager.GetAsync(RolesUrl(registered.UserId)));
        var cleared = await SaveAsync(manager, original);
        Assert.Empty(cleared.Roles);
        Assert.Empty(cleared.Permissions);
        Assert.Empty((await ApiAssert.Data<UserRolesResponse>(user.GetAsync("/api/v1/roles/GetMyRoles"))).Roles);

        var restored = await SaveAsync(manager, cleared, " user ", "USER");
        Assert.Equal(new[] { ApplicationRoles.User }, restored.Roles);
        Assert.Equal(restored.Roles, (await ApiAssert.Data<UserRolesResponse>(user.GetAsync("/api/v1/roles/GetMyRoles"))).Roles);
        var unchanged = await SaveAsync(manager, restored, ApplicationRoles.User);
        Assert.Equal(restored.Version, unchanged.Version);

        // A token issued while Manager must lose its role-management access immediately on demotion.
        using var managerToken = await factory.LoginAsync(appointed.Email);
        var latest = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(appointed.UserId)));
        await SaveAsync(admin, latest, ApplicationRoles.User);
        await ApiAssert.Response<object>(managerToken.GetAsync("/api/v1/roles"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(manager.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new UpdateUserRolesRequest { Version = restored.Version, Roles = [] }), HttpStatusCode.Forbidden);
    }

    [Theory]
    [InlineData(ApplicationRoles.Admin)]
    [InlineData(ApplicationRoles.Manager)]
    public async Task Manager_cannot_grant_privileged_roles_or_change_privileged_accounts(string privilegedRole)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var appointed = await factory.RegisterAsync();
        var managerState = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(appointed.UserId)));
        managerState = await SaveAsync(admin, managerState, ApplicationRoles.Manager);
        using var manager = await factory.LoginAsync(appointed.Email);
        var registered = await factory.RegisterAsync();
        var target = await ApiAssert.Data<UserRolesResponse>(manager.GetAsync(RolesUrl(registered.UserId)));

        var denied = await ApiAssert.Response<object>(manager.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new UpdateUserRolesRequest { Version = target.Version, Roles = [privilegedRole, ApplicationRoles.User] }),
            HttpStatusCode.Forbidden);
        Assert.Equal(ErrorCodes.UserRoles.Forbidden, denied.ErrorCode);
        var unchanged = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(target.Version, unchanged.Version);
        Assert.Equal(target.Roles, unchanged.Roles);

        target = await SaveAsync(admin, target, privilegedRole, ApplicationRoles.User);
        foreach (string[] desired in new[] { Array.Empty<string>(), new[] { ApplicationRoles.User } })
        {
            await ApiAssert.Response<object>(manager.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
                new UpdateUserRolesRequest { Version = target.Version, Roles = desired }), HttpStatusCode.Forbidden);
        }
        unchanged = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(target.Roles, unchanged.Roles);
        Assert.Equal(target.Version, unchanged.Version);

        await ApiAssert.Response<object>(manager.PutAsJsonAsync(UpdateRolesUrl(appointed.UserId),
            new UpdateUserRolesRequest { Version = managerState.Version, Roles = [ApplicationRoles.User] }), HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Ordinary_user_cannot_manage_roles_even_with_all_allowed_direct_permissions()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string permissionsUrl = $"/api/v1/permissions/GetUserPermissions/{registered.UserId}";
        string updatePermissionsUrl = $"/api/v1/permissions/UpdateUserPermissions/{registered.UserId}";
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(permissionsUrl));
        await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersUpdate, Permissions.UsersView] }));
        using var user = await factory.LoginAsync(registered.Email);
        var own = await ApiAssert.Data<UserRolesResponse>(user.GetAsync("/api/v1/roles/GetMyRoles"));
        Assert.Equal(new[] { ApplicationRoles.User }, own.Roles);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, own.Permissions);
        await ApiAssert.Response<object>(user.GetAsync("/api/v1/roles"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.GetAsync(RolesUrl(registered.UserId)), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new UpdateUserRolesRequest { Version = own.Version, Roles = [ApplicationRoles.Admin] }), HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Admin_grants_and_revokes_inherited_permissions_without_removing_direct_or_unrelated_claims()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var account = (await users.FindByIdAsync(registered.UserId))!;
            Assert.True((await users.AddClaimsAsync(account,
                [new Claim("Department", "Support"), new Claim(CustomClaimTypes.Permission, Permissions.UsersView)])).Succeeded);
        }
        using var userToken = await factory.LoginAsync(registered.Email);
        var state = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, state.Permissions);
        var promoted = await SaveAsync(admin, state, ApplicationRoles.Admin, ApplicationRoles.User);
        Assert.Equal(Permissions.All.Order(), promoted.Permissions.Order());
        var granted = await ApiAssert.Data<UserPermissionsResponse>(userToken.GetAsync("/api/v1/permissions/GetMyPermissions"));
        Assert.Equal(Permissions.All.Order(), granted.InheritedPermissions.Order());
        Assert.Equal(granted.EffectivePermissions, promoted.Permissions);
        var ownRoles = await ApiAssert.Data<UserRolesResponse>(userToken.GetAsync("/api/v1/roles/GetMyRoles"));
        Assert.Equal(promoted.Permissions, ownRoles.Permissions);
        var current = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(promoted.Permissions, current.Permissions);
        await ApiAssert.Data<List<RoleDefinitionResponse>>(userToken.GetAsync("/api/v1/roles"));

        using var adminToken = await factory.LoginAsync(registered.Email);
        var demoted = await SaveAsync(admin, promoted, ApplicationRoles.User);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, demoted.Permissions);
        var unchanged = await SaveAsync(admin, demoted, ApplicationRoles.User);
        Assert.Equal(demoted.Permissions, unchanged.Permissions);
        var withoutRoles = await SaveAsync(admin, unchanged);
        Assert.Empty(withoutRoles.Roles);
        Assert.Empty(withoutRoles.Permissions);
        await ApiAssert.Response<object>(userToken.GetAsync("/api/v1/roles"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(adminToken.GetAsync("/api/v1/roles"), HttpStatusCode.Forbidden);
        var revoked = await ApiAssert.Data<UserPermissionsResponse>(adminToken.GetAsync("/api/v1/permissions/GetMyPermissions"));
        Assert.Empty(revoked.InheritedPermissions);
        Assert.Equal(new[] { Permissions.UsersView }, revoked.AssignedPermissions);
        Assert.Empty(revoked.EffectivePermissions);
        Assert.Equal(revoked.EffectivePermissions,
            (await ApiAssert.Data<UserRolesResponse>(adminToken.GetAsync("/api/v1/roles/GetMyRoles"))).Permissions);
        await using var database = factory.CreateDbContext();
        Assert.True(await database.UserClaims.AnyAsync(claim => claim.UserId == registered.UserId &&
            claim.ClaimType == "Department" && claim.ClaimValue == "Support"));
    }

    [Fact]
    public async Task Admin_cannot_remove_own_admin_role()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var own = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync("/api/v1/roles/GetMyRoles"));
        var error = await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdateRolesUrl(own.UserId),
            new UpdateUserRolesRequest { Version = own.Version, Roles = [ApplicationRoles.Manager] }), HttpStatusCode.Forbidden);
        Assert.Equal(ErrorCodes.UserRoles.SelfDemotion, error.ErrorCode);
        var unchanged = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync("/api/v1/roles/GetMyRoles"));
        Assert.Equal(own.Roles, unchanged.Roles);
        Assert.Equal(own.Version, unchanged.Version);
    }

    [Theory]
    [InlineData("CustomRole")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task Invalid_role_names_do_not_change_membership(string? invalid)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        var state = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        var error = await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new { version = state.Version, roles = new[] { ApplicationRoles.Admin, invalid } }), HttpStatusCode.BadRequest);
        Assert.Equal(ErrorCodes.UserRoles.InvalidSelection, error.ErrorCode);
        var unchanged = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(state.Version, unchanged.Version);
        Assert.Equal(state.Roles, unchanged.Roles);
    }

    [Fact]
    public async Task Missing_or_oversized_input_is_rejected_and_unknown_users_return_404()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string url = RolesUrl(registered.UserId);
        string updateRolesUrl = UpdateRolesUrl(registered.UserId);
        var state = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
        object[] invalidRequests =
        [
            new { version = state.Version },
            new { version = state.Version, roles = (string[]?)null },
            new { roles = Array.Empty<string>() },
            new { version = " ", roles = Array.Empty<string>() },
            new { version = new string('v', 129), roles = Array.Empty<string>() },
            new { version = state.Version, roles = Enumerable.Repeat(ApplicationRoles.User, 101).ToArray() }
        ];
        foreach (object request in invalidRequests)
            await ApiAssert.Response<object>(admin.PutAsJsonAsync(updateRolesUrl, request), HttpStatusCode.BadRequest);
        var unchanged = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
        Assert.Equal(state.Roles, unchanged.Roles);
        Assert.Equal(state.Version, unchanged.Version);
        await ApiAssert.Response<object>(admin.GetAsync(RolesUrl("missing-user")), HttpStatusCode.NotFound);
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdateRolesUrl("missing-user"),
            new UpdateUserRolesRequest { Version = state.Version, Roles = [] }), HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Role_and_permission_edits_share_a_version_and_reject_stale_updates()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        var original = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        var promoted = await SaveAsync(admin, original, ApplicationRoles.Manager);
        var staleRole = await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new UpdateUserRolesRequest { Version = original.Version, Roles = [ApplicationRoles.Admin] }), HttpStatusCode.Conflict);
        Assert.Equal(ErrorCodes.UserRoles.Conflict, staleRole.ErrorCode);
        string permissionsUrl = $"/api/v1/permissions/GetUserPermissions/{registered.UserId}";
        string updatePermissionsUrl = $"/api/v1/permissions/UpdateUserPermissions/{registered.UserId}";
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersView] }), HttpStatusCode.Conflict);
        var permissions = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = promoted.Version, Permissions = [Permissions.UsersView] }));
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdateRolesUrl(registered.UserId),
            new UpdateUserRolesRequest { Version = promoted.Version, Roles = [] }), HttpStatusCode.Conflict);
        var current = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(RolesUrl(registered.UserId)));
        Assert.Equal(promoted.Roles, current.Roles);
        Assert.Equal(permissions.Version, current.Version);
    }

    [Fact]
    public async Task Membership_write_failure_rolls_back_the_user_version_and_all_role_changes()
    {
        var failure = new FailRoleWrite();
        await using var factory = await PermissionApiFactory.StartAsync(failure);
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string url = RolesUrl(registered.UserId);
        string updateRolesUrl = UpdateRolesUrl(registered.UserId);
        var original = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
        failure.Armed = true;
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(updateRolesUrl,
            new UpdateUserRolesRequest { Version = original.Version, Roles = [ApplicationRoles.Manager] }), HttpStatusCode.InternalServerError);
        var current = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
        Assert.Equal(original.Version, current.Version);
        Assert.Equal(original.Roles, current.Roles);
    }

    [Fact]
    public async Task Anonymous_requests_are_denied_and_registration_cannot_assign_privileged_roles()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var anonymous = factory.Client();
        await ApiAssert.Response<object>(anonymous.GetAsync("/api/v1/roles"), HttpStatusCode.Unauthorized);
        await ApiAssert.Response<object>(anonymous.GetAsync("/api/v1/roles/GetMyRoles"), HttpStatusCode.Unauthorized);
        await ApiAssert.Response<object>(anonymous.GetAsync(RolesUrl("target")), HttpStatusCode.Unauthorized);
        await ApiAssert.Response<object>(anonymous.PutAsJsonAsync(UpdateRolesUrl("target"),
            new UpdateUserRolesRequest { Version = "version", Roles = [ApplicationRoles.Admin] }), HttpStatusCode.Unauthorized);
        var request = factory.NewRegistration();
        var registered = await ApiAssert.Data<RegisterResponse>(anonymous.PostAsJsonAsync("/api/v1/auth/register", new
        {
            request.Email, request.FullName, request.PhoneNumber, request.Password, request.ConfirmPassword,
            roles = new[] { ApplicationRoles.Admin, ApplicationRoles.Manager }
        }), HttpStatusCode.Created);
        Assert.Equal(new[] { ApplicationRoles.User }, registered.Roles);
    }

    private static Task<UserRolesResponse> SaveAsync(HttpClient actor, UserRolesResponse state, params string[] roles) =>
        ApiAssert.Data<UserRolesResponse>(actor.PutAsJsonAsync(UpdateRolesUrl(state.UserId),
            new UpdateUserRolesRequest { Version = state.Version, Roles = roles }));

    private sealed class FailRoleWrite : SaveChangesInterceptor
    {
        public bool Armed { get; set; }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Armed && eventData.Context!.ChangeTracker.Entries<IdentityUserRole<string>>()
                .Any(entry => entry.State is EntityState.Added or EntityState.Deleted))
                throw new InvalidOperationException("Simulated membership write failure.");
            return ValueTask.FromResult(result);
        }
    }
}
