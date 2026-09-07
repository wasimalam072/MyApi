using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using MyApi.Common.Constants;
using MyApi.Models.Permissions;

namespace MyApi.IntegrationTests;

public sealed class SqlServerFactAttribute : FactAttribute
{
    public SqlServerFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MYAPI_TEST_SQLSERVER")))
            Skip = "Set MYAPI_TEST_SQLSERVER to exercise concurrent SQL Server transactions.";
    }
}

public sealed class PermissionConcurrencyTests
{
    [SqlServerFact]
    public async Task Competing_edits_save_one_complete_set_and_return_one_conflict()
    {
        var barrier = new PermissionWriteBarrier();
        await using var factory = await PermissionApiFactory.StartAsync(barrier);
        using var admin = await factory.LoginAsync(factory.AdminEmail);
        var registered = await factory.RegisterAsync();
        string url = $"/api/v1/permissions/users/{registered.UserId}";
        var original = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));

        var responses = await Task.WhenAll(
            admin.PutAsJsonAsync(url, new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersView] }),
            admin.PutAsJsonAsync(url, new UpdateUserPermissionsRequest { Version = original.Version, Permissions = [Permissions.UsersDelete] }))
            .WaitAsync(TimeSpan.FromSeconds(45));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Conflict);
            var winner = await responses.Single(response => response.StatusCode == HttpStatusCode.OK)
                .Content.ReadFromJsonAsync<ApiResponse<UserPermissionsResponse>>();
            var current = await ApiAssert.Data<UserPermissionsResponse>(admin.GetAsync(url));
            Assert.Equal(winner!.Data!.AssignedPermissions, current.AssignedPermissions);
            Assert.Single(current.AssignedPermissions);
            Assert.Equal(winner.Data.Version, current.Version);
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    private sealed class PermissionWriteBarrier : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrivals;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<IdentityUserClaim<string>>()
                .Any(entry => entry.Entity.ClaimType == CustomClaimTypes.Permission && entry.State == EntityState.Added))
            {
                if (Interlocked.Increment(ref _arrivals) == 2) _ready.TrySetResult();
                await _ready.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
            }
            return result;
        }
    }
}
