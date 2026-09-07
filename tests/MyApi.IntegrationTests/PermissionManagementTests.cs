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
    private static string PermissionsUrl(string userId) => $"/api/v1/permissions/users/{userId}";

    [Theory]
    [InlineData(ApplicationRoles.Admin)]
    [InlineData(ApplicationRoles.Manager)]
    public async Task Administrator_can_grant_replace_and_revoke_permissions_for_existing_tokens(string actorRole)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var actor = await LoginActorAsync(factory, actorRole);
        var registered = await factory.RegisterAsync();
        using var user = await factory.LoginAsync(registered.Email);
        string url = PermissionsUrl(registered.UserId);

        var catalog = await ApiAssert.Data<List<PermissionDefinitionResponse>>(actor.GetAsync("/api/v1/permissions"));
        Assert.Equal(Permissions.All.Order(), catalog.Select(permission => permission.Name).Order());
        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        var original = await ApiAssert.Data<UserPermissionsResponse>(actor.GetAsync(url));

        var granted = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [" users.view ", "Users.View"] }));
        Assert.Equal(new[] { Permissions.UsersView }, granted.AssignedPermissions);
        Assert.Equal(granted.AssignedPermissions, granted.EffectivePermissions);
        Assert.NotEqual(original.Version, granted.Version);
        await ApiAssert.Data<List<RegisteredUserResponse>>(user.GetAsync(ListUsers));
        var ownPermissions = await ApiAssert.Data<UserPermissionsResponse>(user.GetAsync("/api/v1/permissions/me"));
        Assert.Equal(granted.EffectivePermissions, ownPermissions.EffectivePermissions);

        // This token contains Users.View in its original claims. Revocation must
        // remove that old snapshot as well as deny the token issued before grant.
        using var tokenWithGrant = await factory.LoginAsync(registered.Email);
        var replaced = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = granted.Version, Permissions = [Permissions.UsersUpdate] }));
        Assert.Equal(new[] { Permissions.UsersUpdate }, replaced.EffectivePermissions);
        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(tokenWithGrant.GetAsync(ListUsers), HttpStatusCode.Forbidden);

        var target = await factory.RegisterAsync();
        string updateUrl = $"/api/v1/adminusers/UpdateUser/{target.UserId}";
        var update = new UpdateUserRequest { FullName = "Changed by delegated user", PhoneNumber = "+15555550102" };
        var updated = await ApiAssert.Data<RegisteredUserResponse>(user.PutAsJsonAsync(updateUrl, update));
        Assert.Equal(target.UserId, updated.UserId);
        Assert.Equal(update.FullName, updated.FullName);

        var revoked = await ApiAssert.Data<UserPermissionsResponse>(actor.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = replaced.Version, Permissions = [] }));
        Assert.Empty(revoked.AssignedPermissions);
        Assert.Empty(revoked.EffectivePermissions);
        await ApiAssert.Response<object>(user.PutAsJsonAsync(updateUrl, update), HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task User_cannot_delegate_permissions_even_with_user_management_permissions()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        using var user = await factory.LoginAsync(registered.Email);
        string url = PermissionsUrl(registered.UserId);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var granted = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = Permissions.All.ToArray() }));

        await ApiAssert.Response<object>(user.GetAsync("/api/v1/permissions"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.GetAsync(url), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.PutAsJsonAsync(url,
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
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var granted = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersView] }));

        var error = await ApiAssert.Response<object>(admin.PutAsJsonAsync(url,
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
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(url, new { version = state.Version }), HttpStatusCode.BadRequest);
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(url, new { permissions = Array.Empty<string>() }), HttpStatusCode.BadRequest);
        await ApiAssert.Response<object>(admin.GetAsync(PermissionsUrl("missing-user")), HttpStatusCode.NotFound);
        await ApiAssert.Response<object>(admin.PutAsJsonAsync(PermissionsUrl("missing-user"),
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
        var original = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var saved = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersView] }));

        var conflict = await ApiAssert.Response<object>(manager.PutAsJsonAsync(url,
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
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
        var added = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersDelete] }));
        var cleared = await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(url,
            new UpdateUserPermissionsRequest { Version = added.Version, Permissions = [] }));
        Assert.Empty(cleared.AssignedPermissions);
        Assert.Equal(new[] { Permissions.UsersView }, cleared.InheritedPermissions);
        Assert.Equal(cleared.InheritedPermissions, cleared.EffectivePermissions);
        await using var database = factory.CreateDbContext();
        Assert.True(await database.UserClaims.AnyAsync(claim => claim.UserId == registered.UserId && claim.ClaimType == "Department" && claim.ClaimValue == "Support"));
    }

    [Fact]
    public async Task Delegated_create_and_delete_permissions_control_the_management_endpoints()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        using var user = await factory.LoginAsync(registered.Email);
        var request = factory.NewRegistration();
        const string createUrl = "/api/v1/adminusers/CreateUser";
        await ApiAssert.Response<object>(user.PostAsJsonAsync(createUrl, request), HttpStatusCode.Forbidden);
        var state = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(PermissionsUrl(registered.UserId)));
        await ApiAssert.Data<UserPermissionsResponse>(admin.PutAsJsonAsync(PermissionsUrl(registered.UserId),
            new UpdateUserPermissionsRequest { Version = state.Version, Permissions = [Permissions.UsersCreate, Permissions.UsersDelete] }));

        var created = await ApiAssert.Data<RegisterResponse>(user.PostAsJsonAsync(createUrl, request), HttpStatusCode.Created);
        Assert.Equal(new[] { ApplicationRoles.User }, created.Roles);
        var deleted = await ApiAssert.Data<DeleteUserResponse>(user.DeleteAsync($"/api/v1/adminusers/DeleteUser/{created.UserId}"));
        Assert.Equal(created.UserId, deleted.UserId);
        await using var database = factory.CreateDbContext();
        Assert.False(await database.Users.AnyAsync(account => account.Id == created.UserId));
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
        await ApiAssert.Response<object>(manager.GetAsync("/api/v1/permissions/me"), HttpStatusCode.Unauthorized);
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
