namespace MyApi.Data.Seed;

/// <summary>
/// Initializes required ASP.NET Core Identity data.
/// </summary>
public static class IdentitySeeder
{
    public static async Task SeedAsync(
        IServiceProvider serviceProvider,
        IConfiguration configuration)
    {
        using IServiceScope scope =
            serviceProvider.CreateScope();

        RoleManager<IdentityRole> roleManager =
            scope.ServiceProvider
                .GetRequiredService<
                    RoleManager<IdentityRole>>();

        UserManager<ApplicationUser> userManager =
            scope.ServiceProvider
                .GetRequiredService<
                    UserManager<ApplicationUser>>();

        // Order is important:
        // Roles must exist before permissions or users
        // can be assigned to those roles.
        await SeedRolesAsync(
            roleManager);

        await SeedRolePermissionsAsync(
            scope.ServiceProvider.GetRequiredService<ApplicationDbContext>());

        await SeedInitialAdministratorAsync(
            userManager,
            configuration);
    }

    private static async Task SeedRolesAsync(
        RoleManager<IdentityRole> roleManager)
    {
        foreach (string roleName in ApplicationRoles.All)
        {
            if (await roleManager.RoleExistsAsync(roleName))
            {
                continue;
            }

            IdentityResult result =
                await roleManager.CreateAsync(
                    new IdentityRole(roleName));

            EnsureSucceeded(
                result,
                $"Creating role '{roleName}'");
        }
    }

    private static async Task SeedRolePermissionsAsync(ApplicationDbContext database)
    {
        foreach (string roleName in ApplicationRoles.All)
        {
            IdentityRole role = await database.Roles.SingleAsync(role => role.Name == roleName);
            List<IdentityRoleClaim<string>> existing = await database.RoleClaims
                .Where(claim => claim.RoleId == role.Id && claim.ClaimType == CustomClaimTypes.Permission)
                .ToListAsync();
            IReadOnlyList<string> desired = RolePermissions.ForRole(roleName);
            if (existing.Select(claim => claim.ClaimValue).OrderBy(value => value, StringComparer.Ordinal)
                .SequenceEqual(desired, StringComparer.Ordinal)) continue;

            // Reconcile existing installations as well as new databases. Other role claims are preserved.
            database.RoleClaims.RemoveRange(existing);
            database.RoleClaims.AddRange(desired.Select(permission => new IdentityRoleClaim<string>
            {
                RoleId = role.Id,
                ClaimType = CustomClaimTypes.Permission,
                ClaimValue = permission
            }));
            role.ConcurrencyStamp = Guid.NewGuid().ToString();
        }

        // Publish the complete role-permission matrix in one transaction.
        await database.SaveChangesAsync();
    }

    private static async Task SeedInitialAdministratorAsync(
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration)
    {
        string? email =
            configuration["InitialAdmin:Email"];

        string? password =
            configuration["InitialAdmin:Password"];

        // Initial admin creation is optional.
        if (string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        email =
            email.Trim().ToLowerInvariant();

        ApplicationUser? admin =
            await userManager.FindByEmailAsync(
                email);

        if (admin is null)
        {
            admin =
                new ApplicationUser
                {
                    FullName =
                        configuration[
                            "InitialAdmin:FullName"]
                        ?.Trim()
                        ?? "System Administrator",

                    UserName = email,
                    Email = email,

                    PhoneNumber =
                        configuration[
                            "InitialAdmin:PhoneNumber"]
                        ?.Trim(),

                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true
                };

            IdentityResult createResult =
                await userManager.CreateAsync(
                    admin,
                    password);

            EnsureSucceeded(
                createResult,
                "Creating initial administrator");
        }

        // Ensure the initial account always has Admin role.
        if (!await userManager.IsInRoleAsync(
                admin,
                ApplicationRoles.Admin))
        {
            IdentityResult roleResult =
                await userManager.AddToRoleAsync(
                    admin,
                    ApplicationRoles.Admin);

            EnsureSucceeded(
                roleResult,
                "Assigning Admin role to initial administrator");
        }
    }

    private static void EnsureSucceeded(
        IdentityResult result,
        string operation)
    {
        if (result.Succeeded)
        {
            return;
        }

        string errors =
            string.Join(
                ", ",
                result.Errors.Select(
                    error =>
                        $"{error.Code}: {error.Description}"));

        throw new InvalidOperationException(
            $"{operation} failed. {errors}");
    }
}
