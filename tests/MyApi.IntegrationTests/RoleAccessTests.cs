using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MyApi.Common.Constants;
using MyApi.Models.Auth;
using MyApi.Models.Permissions;
using MyApi.Models.Roles;
using MyApi.Models.Users;

namespace MyApi.IntegrationTests;

public sealed class RoleAccessTests
{
    private const string ListUsers = "/api/v1/adminusers/AllRegisteredUsers";
    private const string OwnProfile = "/api/v1/users/GetCurrentUser";
    private const string UpdateOwnProfile = "/api/v1/users/UpdateUser";

    [Theory]
    [InlineData(ApplicationRoles.Admin, "Users.Create,Users.Delete,Users.Update,Users.View")]
    [InlineData(ApplicationRoles.Manager, "Users.Create,Users.Update,Users.View")]
    [InlineData(ApplicationRoles.User, "Users.Update,Users.View")]
    public async Task Permissions_match_the_role_in_login_token_profile_and_authorization_responses(string role, string expectedNames)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, registered.Permissions);
        var saved = await SetRolesAsync(admin, registered.UserId, role);
        string[] expected = expectedNames.Split(',');
        Assert.Equal(expected, saved.Permissions);

        using var anonymous = factory.Client();
        var login = await ApiAssert.Data<LoginResponse>(anonymous.PostAsJsonAsync("/api/v1/auth/login",
            new LoginRequest { Email = registered.Email, Password = factory.Password }));
        Assert.Equal(expected, login.Permissions);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(login.AccessToken);
        Assert.Equal(expected, token.Claims.Where(claim => claim.Type == CustomClaimTypes.Permission).Select(claim => claim.Value));
        using var client = factory.Client(login.AccessToken);
        Assert.Equal(expected, (await ApiAssert.Data<RegisteredUserResponse>(client.GetAsync(OwnProfile))).Permissions);
        Assert.Equal(expected, (await ApiAssert.Data<UserRolesResponse>(client.GetAsync("/api/v1/roles/GetMyRoles"))).Permissions);
        Assert.Equal(expected, (await ApiAssert.Data<UserPermissionsResponse>(client.GetAsync("/api/v1/permissions/GetMyPermissions"))).EffectivePermissions);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task User_can_only_read_and_update_own_account_even_with_legacy_privileged_grants(bool legacyGrants)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        var registered = await factory.RegisterAsync();
        var other = await factory.RegisterAsync();
        if (legacyGrants) await AddLegacyGrantsAsync(factory, registered.UserId);
        using var user = await factory.LoginAsync(registered.Email);

        var profile = await ApiAssert.Data<RegisteredUserResponse>(user.GetAsync($"{OwnProfile}?userId={other.UserId}"));
        Assert.Equal(registered.UserId, profile.UserId);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, profile.Permissions);
        var updated = await ApiAssert.Data<RegisteredUserResponse>(user.PutAsJsonAsync($"{UpdateOwnProfile}?userId={other.UserId}", new
        {
            fullName = "My own updated name", phoneNumber = "+15555550200", userId = other.UserId
        }));
        Assert.Equal(registered.UserId, updated.UserId);
        Assert.Equal("My own updated name", updated.FullName);

        await ApiAssert.Response<object>(user.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.PostAsJsonAsync("/api/v1/adminusers/CreateUser", factory.NewRegistration()), HttpStatusCode.Forbidden);
        foreach (string target in new[] { registered.UserId, other.UserId })
        {
            await ApiAssert.Response<object>(user.PutAsJsonAsync($"/api/v1/adminusers/UpdateUser/{target}",
                new UpdateUserRequest { FullName = "Forbidden update", PhoneNumber = "+15555550201" }), HttpStatusCode.Forbidden);
            await ApiAssert.Response<object>(user.DeleteAsync($"/api/v1/adminusers/DeleteUser/{target}"), HttpStatusCode.Forbidden);
        }
        await ApiAssert.Response<object>(user.GetAsync($"/api/v1/roles/GetUserRoles/{other.UserId}"), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(user.GetAsync($"/api/v1/permissions/GetUserPermissions/{other.UserId}"), HttpStatusCode.Forbidden);

        await using var database = factory.CreateDbContext();
        var unchanged = await database.Users.SingleAsync(account => account.Id == other.UserId);
        Assert.Equal(other.FullName, unchanged.FullName);
        Assert.Equal(other.PhoneNumber, unchanged.PhoneNumber);
        Assert.True(await database.Users.AnyAsync(account => account.Id == registered.UserId));
    }

    [Theory]
    [InlineData(ApplicationRoles.Admin)]
    [InlineData(ApplicationRoles.Manager)]
    public async Task Admin_and_manager_can_manage_users_but_only_admin_can_delete(string role)
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        await SetRolesAsync(admin, registered.UserId, role);
        await AddLegacyGrantsAsync(factory, registered.UserId);
        using var actor = await factory.LoginAsync(registered.Email);

        var created = await ApiAssert.Data<RegisterResponse>(actor.PostAsJsonAsync("/api/v1/adminusers/CreateUser", factory.NewRegistration()), HttpStatusCode.Created);
        Assert.Equal(new[] { ApplicationRoles.User }, created.Roles);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView }, created.Permissions);
        var users = await ApiAssert.Data<List<RegisteredUserResponse>>(actor.GetAsync(ListUsers));
        Assert.Contains(users, user => user.UserId == created.UserId);
        var updated = await ApiAssert.Data<RegisteredUserResponse>(actor.PutAsJsonAsync($"/api/v1/adminusers/UpdateUser/{created.UserId}",
            new UpdateUserRequest { FullName = "Updated by management", PhoneNumber = "+15555550202" }));
        Assert.Equal(created.UserId, updated.UserId);
        Assert.Equal("Updated by management", updated.FullName);

        if (role == ApplicationRoles.Admin)
        {
            var deleted = await ApiAssert.Data<DeleteUserResponse>(actor.DeleteAsync($"/api/v1/adminusers/DeleteUser/{created.UserId}"));
            Assert.Equal(created.UserId, deleted.UserId);
        }
        else
        {
            var own = await ApiAssert.Data<RegisteredUserResponse>(actor.GetAsync(OwnProfile));
            Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView }, own.Permissions);
            await ApiAssert.Response<object>(actor.DeleteAsync($"/api/v1/adminusers/DeleteUser/{created.UserId}"), HttpStatusCode.Forbidden);
            await using var database = factory.CreateDbContext();
            Assert.True(await database.Users.AnyAsync(account => account.Id == created.UserId));
        }
    }

    [Fact]
    public async Task Demotion_limits_existing_tokens_and_direct_grants_to_current_role_scope()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        var target = await factory.RegisterAsync();
        await SetRolesAsync(admin, registered.UserId, ApplicationRoles.Admin);
        await AddLegacyGrantsAsync(factory, registered.UserId);
        using var oldAdminToken = await factory.LoginAsync(registered.Email);
        await ApiAssert.Data<List<RegisteredUserResponse>>(oldAdminToken.GetAsync(ListUsers));

        await SetRolesAsync(admin, registered.UserId, ApplicationRoles.Manager);
        await ApiAssert.Response<object>(oldAdminToken.DeleteAsync($"/api/v1/adminusers/DeleteUser/{target.UserId}"), HttpStatusCode.Forbidden);
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView },
            (await ApiAssert.Data<RegisteredUserResponse>(oldAdminToken.GetAsync(OwnProfile))).Permissions);

        await SetRolesAsync(admin, registered.UserId, ApplicationRoles.User);
        await ApiAssert.Response<object>(oldAdminToken.GetAsync(ListUsers), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(oldAdminToken.PostAsJsonAsync("/api/v1/adminusers/CreateUser", factory.NewRegistration()), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(oldAdminToken.PutAsJsonAsync($"/api/v1/adminusers/UpdateUser/{target.UserId}",
            new UpdateUserRequest { FullName = "Forbidden update", PhoneNumber = "+15555550203" }), HttpStatusCode.Forbidden);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView },
            (await ApiAssert.Data<RegisteredUserResponse>(oldAdminToken.GetAsync(OwnProfile))).Permissions);

        await SetRolesAsync(admin, registered.UserId);
        await ApiAssert.Response<object>(oldAdminToken.GetAsync(OwnProfile), HttpStatusCode.Forbidden);
        await ApiAssert.Response<object>(oldAdminToken.PutAsJsonAsync(UpdateOwnProfile,
            new UpdateUserRequest { FullName = "Forbidden update", PhoneNumber = "+15555550203" }), HttpStatusCode.Forbidden);
        Assert.Empty((await ApiAssert.Data<UserRolesResponse>(oldAdminToken.GetAsync("/api/v1/roles/GetMyRoles"))).Permissions);
    }

    private static async Task<UserRolesResponse> SetRolesAsync(HttpClient admin, string userId, params string[] roles)
    {
        var state = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync($"/api/v1/roles/GetUserRoles/{userId}"));
        return await ApiAssert.Data<UserRolesResponse>(admin.PutAsJsonAsync($"/api/v1/roles/UpdateUserRoles/{userId}",
            new UpdateUserRolesRequest { Version = state.Version, Roles = roles }));
    }

    private static async Task AddLegacyGrantsAsync(PermissionApiFactory factory, string userId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await users.FindByIdAsync(userId))!;
        Assert.True((await users.AddClaimsAsync(user,
            Permissions.All.Select(permission => new Claim(CustomClaimTypes.Permission, permission)))).Succeeded);
    }
}
