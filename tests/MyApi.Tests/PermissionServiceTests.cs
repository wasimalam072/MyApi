using System.Security.Claims;
using MyApi.Common.Constants;
using MyApi.Features.Users;

namespace MyApi.Tests;

public sealed class PermissionServiceTests
{
    [Fact]
    public async Task Permissions_merge_direct_and_role_claims_and_ignore_invalid_or_duplicate_claims()
    {
        using var context = new AuthTestContext();
        context.Users.Claims =
        [
            new Claim(CustomClaimTypes.Permission, "Test.Write"),
            new Claim(CustomClaimTypes.Permission, "test.read"),
            new Claim(CustomClaimTypes.Permission, " "),
            new Claim(ClaimTypes.Name, "NotAPermission")
        ];
        context.Roles.Claims[context.Roles.RolesByName[ApplicationRoles.User].Id] =
        [
            new Claim(CustomClaimTypes.Permission, "Test.Read"),
            new Claim(CustomClaimTypes.Permission, "Test.Delete"),
            new Claim(CustomClaimTypes.Permission, "")
        ];

        var result = await context.Permissions.GetEffectivePermissionsAsync(
            AuthServiceTests.User(), new[] { ApplicationRoles.User, "USER", "MissingRole" });

        Assert.Equal(new[] { "Test.Delete", "test.read", "Test.Write" }, result);
        Assert.Equal(0, context.Users.RoleQueries);
        Assert.Equal(2, context.Roles.RoleQueries);
        Assert.Equal(1, context.Roles.ClaimQueries);
    }

    [Fact]
    public async Task Profile_mapping_reuses_loaded_roles_when_resolving_permissions()
    {
        using var context = new AuthTestContext();
        var mapper = new UserResponseMapper(context.Users, context.Permissions);
        context.Users.RoleNames = [ApplicationRoles.User, "USER"];
        context.Users.Claims = [new Claim(CustomClaimTypes.Permission, "Test.Read")];
        var response = await mapper.MapAsync(AuthServiceTests.User());

        Assert.Equal("test-user", response.UserId);
        Assert.Equal(new[] { ApplicationRoles.User }, response.Roles);
        Assert.Equal(new[] { "Test.Read" }, response.Permissions);
        Assert.Equal(1, context.Users.RoleQueries);
        Assert.Equal(1, context.Users.ClaimQueries);
    }
}
