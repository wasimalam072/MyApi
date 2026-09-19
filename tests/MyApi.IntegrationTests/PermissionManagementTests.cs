using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MyApi.Common.Constants;
using MyApi.Models.Auth;
using MyApi.Models.Permissions;
using MyApi.Models.Users;

namespace MyApi.IntegrationTests;

public sealed class PermissionManagementTests
{
    private const string ListUsers = "/api/v1/adminusers/AllRegisteredUsers";
    private static string PermissionsUrl(string userId) => $"/api/v1/permissions/GetUserPermissions/{userId}";
    private static string UpdatePermissionsUrl(string userId) => $"/api/v1/permissions/UpdateUserPermissions/{userId}";

    [Theory]
    [InlineData(ApplicationRoles.Admin)]
    [InlineData(ApplicationRoles.Manager)]
    public async Task Direct_grants_can_be_edited_without_removing_inherited_permissions_or_expanding_user_scope(string actorRole)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var actor = await LoginActorAsync(factory, actorRole);
        var registered = await factory.RegisterAsync();
        using var user = await factory.LoginAsync(registered.Email);
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);

        var catalog = await ApiAssert.Data<List<PermissionDefinitionResponse>>(actor.GetAsync("/api/v1/permissions"));
        Assert.Equal(Permissions.All.Order(), catalog.Select(permission => permission.Name).Order());
        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        var original = await ApiAssert.Data<UserPermissionsResponse>(actor.GetAsync(url));

        var granted = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [" users.view ", "Users.View"] }));
        Assert.Equal(new[] { Permissions.UsersView }, granted.AssignedPermissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, granted.EffectivePermissions);
        Assert.NotEqual(original.Version, granted.Version);
        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        var ownPermissions = await ApiAssert.Data<UserPermissionsResponse>(user.GetAsync("/api/v1/permissions/GetMyPermissions"));
        Assert.Equal(granted.EffectivePermissions, ownPermissions.EffectivePermissions);

        // A permission claim never grants a standard User access to other accounts.
        using var tokenWithGrant = await factory.LoginAsync(registered.Email);
        var replaced = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = granted.Version, Permissions = [Permissions.UsersUpdate] }));
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, replaced.EffectivePermissions);
        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(tokenWithGrant.GetAsync(ListUsers), HttpStatusCode.Forbidden);

        var target = await factory.RegisterAsync();
        string updateUrl = $"/api/v1/adminusers/UpdateUser/{target.UserId}";
        var update = new UpdateUserRequest { FullName = "Changed by delegated user", PhoneNumber = "+15555550102" };
        await ApiAssert.Response<object>(user.PutAsJsonAsync(updateUrl, update), HttpStatusCode.Forbidden);

        var revoked = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = replaced.Version, Permissions = [] }));
        Assert.Empty(revoked.AssignedPermissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, revoked.EffectivePermissions);
        await ApiAssert.Response<object>(user.PutAsJsonAsync(updateUrl, update), HttpStatusCode.Forbidden);
        var own = await ApiAssert.Data<RegisteredUserResponse>(user.GetAsync("/api/v1/users/GetCurrentUser"));
        Assert.Equal(registered.UserId, own.UserId);
    }

    [Fact]
    public async Task User_cannot_delegate_permissions_even_with_user_management_permissions()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        using var user = await factory.LoginAsync(registered.Email);
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var granted = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersUpdate, Permissions.UsersView] }));

        await ApiAssert.Response<object>(user.GetAsync("/api/v1/permissions"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.GetAsync(url), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = granted.Version, Permissions = [] }), HttpStatusCode.Forbidden);
        var unchanged = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        Assert.Equal(granted.Version, unchanged.Version);
        Assert.Equal(granted.AssignedPermissions, unchanged.AssignedPermissions);
    }

    [Theory]
    [InlineData("Unknown.Permission")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public async Task Invalid_permissions_are_rejected_without_changing_existing_grants(string? invalid)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var granted = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersView] }));

        var error = await ApiAssert.Response<object>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new { version = granted.Version, permissions = new[] { Permissions.UsersDelete, invalid } }), HttpStatusCode.BadRequest);
        Assert.Equal(ErrorCodes.UserPermissions.InvalidSelection, error.ErrorCode);
        var unchanged = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        Assert.Equal(granted.Version, unchanged.Version);
        Assert.Equal(granted.AssignedPermissions, unchanged.AssignedPermissions);
    }

    [Fact]
    public async Task Missing_list_or_version_is_rejected_and_unknown_users_return_404()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(updatePermissionsUrl, new { version = state.Version }), HttpStatusCode.BadRequest);
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(updatePermissionsUrl, new { permissions = Array.Empty<string>() }), HttpStatusCode.BadRequest);
        await ApiAssert.Response<object>(admin.GetAsync(PermissionsUrl("missing-user")), HttpStatusCode.NotFound);
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdatePermissionsUrl("missing-user"),
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [] }), HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Stale_version_cannot_overwrite_another_administrators_changes()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        using var manager = await LoginActorAsync(factory, ApplicationRoles.Manager);
        var registered = await factory.RegisterAsync();
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);
        var original = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var saved = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersView] }));

        var conflict = await ApiAssert.Response<object>(manager.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersDelete] }), HttpStatusCode.Conflict);
        Assert.Equal(ErrorCodes.UserPermissions.Conflict, conflict.ErrorCode);
        var current = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        Assert.Equal(saved.Version, current.Version);
        Assert.Equal(saved.AssignedPermissions, current.AssignedPermissions);
    }

    [Fact]
    public async Task Replacing_direct_permissions_preserves_role_permissions_and_unrelated_claims()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var role = (await roles.FindByNameAsync(ApplicationRoles.User))!;
            Assert.True((await roles.AddClaimAsync(role, new Claim(CustomClaimTypes.Permission, Permissions.UsersView))).Succeeded);
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var account = (await users.FindByIdAsync(registered.UserId))!;
            Assert.True((await users.AddClaimAsync(account, new Claim("Department", "Support"))).Succeeded);
        }
        string url = PermissionsUrl(registered.UserId);
        string updatePermissionsUrl = UpdatePermissionsUrl(registered.UserId);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var added = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersUpdate] }));
        var cleared = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(updatePermissionsUrl,
            new UpdateUserPermissionsRequest { Version = added.Version, Permissions = [] }));
        Assert.Empty(cleared.AssignedPermissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, cleared.InheritedPermissions);
        Assert.Equal(cleared.InheritedPermissions, cleared.EffectivePermissions);
        await using var database = factory.CreateDbContext();
        Assert.True(await database.UserClaims.AnyAsync(claim => claim.UserId == registered.UserId && claim.ClaimType == "Department" && claim.ClaimValue == "Support"));
    }

    [Theory]
    [InlineData(ApplicationRoles.User, Permissions.UsersCreate)]
    [InlineData(ApplicationRoles.User, Permissions.UsersDelete)]
    [InlineData(ApplicationRoles.Manager, Permissions.UsersDelete)]
    public async Task Direct_grants_cannot_exceed_the_target_users_role(string role, string forbiddenPermission)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        if (role == ApplicationRoles.Manager)
            await SetRoleAsync(factory, registered.UserId, ApplicationRoles.Manager, add: true);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(PermissionsUrl(registered.UserId)));
        var failure = await ApiAssert.Response<object>(admin.PutAsJsonAsync(UpdatePermissionsUrl(registered.UserId),
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [forbiddenPermission] }), HttpStatusCode.BadRequest);
        Assert.Equal(ErrorCodes.UserPermissions.InvalidSelection, failure.ErrorCode);
        var current = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(PermissionsUrl(registered.UserId)));
        Assert.Equal(state.Version, current.Version);
        Assert.Equal(state.AssignedPermissions, current.AssignedPermissions);
        Assert.Equal(state.EffectivePermissions, current.EffectivePermissions);
    }

    [Fact]
    public async Task Removed_manager_role_and_deleted_accounts_cannot_use_old_tokens()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        var registered = await factory.RegisterAsync();
        await SetRoleAsync(factory, registered.UserId, ApplicationRoles.Manager, add: true);
        using var manager = await factory.LoginAsync(registered.Email);
        await ApiAssert.Data<List<PermissionDefinitionResponse>>(manager.GetAsync("/api/v1/permissions"));
        await SetRoleAsync(factory, registered.UserId, ApplicationRoles.Manager, add: false);
        await ApiAssert.Response<object>(manager.GetAsync("/api/v1/permissions"), HttpStatusCode.Forbidden);

        using var admin = await factory.LoginAsync(factory.AdminEmail);
        await ApiAssert.Data<DeleteUserResponse>(admin.DeleteAsync($"/api/v1/adminusers/DeleteUser/{registered.UserId}"));
        await ApiAssert.Response<object>(manager.GetAsync("/api/v1/permissions/GetMyPermissions"), HttpStatusCode.Unauthorized);
    }

    private static async Task<HttpClient> LoginActorAsync(PermissionApiFactory factory, string role)
    {
        if (role == ApplicationRoles.Admin) return await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        await SetRoleAsync(factory, registered.UserId, role, add: true);
        return await factory.LoginAsync(registered.Email);
    }

    private static async Task SetRoleAsync(PermissionApiFactory factory, string userId, string role, bool add)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await users.FindByIdAsync(userId))!;
        Assert.True((add ? await users.AddToRoleAsync(user, role) : await users.RemoveFromRoleAsync(user, role)).Succeeded);
    }
}
