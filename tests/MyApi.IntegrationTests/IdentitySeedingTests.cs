using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MyApi.Common.Constants;
using MyApi.Data.Seed;
using MyApi.Models.Roles;

namespace MyApi.IntegrationTests;

public sealed class IdentitySeedingTests
{
    [Fact]
    public async Task Seeding_repairs_existing_role_grants_preserves_other_claims_and_is_idempotent()
    {
        await using var factory = await PermissionApiFactory.StartAsync();
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        await using (var database = factory.CreateDbContext())
        {
            database.RoleClaims.RemoveRange(await database.RoleClaims.ToListAsync());
            foreach (var role in await database.Roles.ToListAsync())
            {
                database.RoleClaims.AddRange(
                    new IdentityRoleClaim<string> { RoleId = role.Id, ClaimType = CustomClaimTypes.Permission, ClaimValue = "users.view" },
                    new IdentityRoleClaim<string> { RoleId = role.Id, ClaimType = CustomClaimTypes.Permission, ClaimValue = "users.view" },
                    new IdentityRoleClaim<string> { RoleId = role.Id, ClaimType = CustomClaimTypes.Permission, ClaimValue = Permissions.UsersDelete },
                    new IdentityRoleClaim<string> { RoleId = role.Id, ClaimType = CustomClaimTypes.Permission, ClaimValue = "Unknown.Permission" },
                    new IdentityRoleClaim<string> { RoleId = role.Id, ClaimType = "Department", ClaimValue = "Support" });
            }
            await database.SaveChangesAsync();
        }

        var configuration = factory.Services.GetRequiredService<IConfiguration>();
        await IdentitySeeder.SeedAsync(factory.Services, configuration);
        var catalog = await ApiAssert.Data<List<RoleDefinitionResponse>>(admin.GetAsync("/api/v1/roles"));
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersDelete, Permissions.UsersUpdate, Permissions.UsersView },
            catalog.Single(role => role.Name == ApplicationRoles.Admin).Permissions);
        Assert.Equal(new[] { Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView },
            catalog.Single(role => role.Name == ApplicationRoles.Manager).Permissions);
        Assert.Equal(new[] { Permissions.UsersUpdate, Permissions.UsersView },
            catalog.Single(role => role.Name == ApplicationRoles.User).Permissions);

        await using var check = factory.CreateDbContext();
        Assert.Equal(9, await check.RoleClaims.CountAsync(claim => claim.ClaimType == CustomClaimTypes.Permission));
        Assert.Equal(3, await check.RoleClaims.CountAsync(claim => claim.ClaimType == "Department" && claim.ClaimValue == "Support"));
        var claimIds = await check.RoleClaims.OrderBy(claim => claim.Id).Select(claim => claim.Id).ToArrayAsync();
        var stamps = await check.Roles.OrderBy(role => role.Name).Select(role => role.ConcurrencyStamp).ToArrayAsync();

        await IdentitySeeder.SeedAsync(factory.Services, configuration);
        Assert.Equal(claimIds, await check.RoleClaims.OrderBy(claim => claim.Id).Select(claim => claim.Id).ToArrayAsync());
        Assert.Equal(stamps, await check.Roles.OrderBy(role => role.Name).Select(role => role.ConcurrencyStamp).ToArrayAsync());
    }
}
