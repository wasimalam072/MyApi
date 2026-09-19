using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore.Diagnostics;
using MyApi.Common.Constants;
using MyApi.Models.Auth;
using MyApi.Models.Roles;

namespace MyApi.IntegrationTests;

public sealed class RoleConcurrencyTests
{
    [SqlServerFact]
    public async Task Competing_role_edits_commit_one_complete_set_and_return_one_conflict()
    {
        // Identical grants also need to return a version conflict, rather than
        // fail on the unique user/role key or silently accept a stale update.
        foreach (string secondRole in new[] { ApplicationRoles.Admin, ApplicationRoles.Manager })
        {
            var barrier = new RoleWriteBarrier();
            await using var factory = await PermissionApiFactory.StartAsync(barrier);
            using var admin = await factory.LoginAsync(factory.AdminEmail);
            var registered = await factory.RegisterAsync();
            string url = $"/api/v1/roles/GetUserRoles/{registered.UserId}";
            string updateUrl = $"/api/v1/roles/UpdateUserRoles/{registered.UserId}";
            var original = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
            barrier.TargetUserId = registered.UserId;

            var responses = await Task.WhenAll(
                admin.PutAsJsonAsync(updateUrl, new UpdateUserRolesRequest { Version = original.Version, Roles = [ApplicationRoles.Admin] }),
                admin.PutAsJsonAsync(updateUrl, new UpdateUserRolesRequest { Version = original.Version, Roles = [secondRole] }))
                .WaitAsync(TimeSpan.FromSeconds(45));
            try
            {
                Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
                Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Conflict);
                var winner = await responses.Single(response => response.StatusCode == HttpStatusCode.OK)
                    .Content.ReadFromJsonAsync<ApiResponse<UserRolesResponse>>();
                var conflict = await responses.Single(response => response.StatusCode == HttpStatusCode.Conflict)
                    .Content.ReadFromJsonAsync<ApiResponse<object>>();
                Assert.Equal(ErrorCodes.UserRoles.Conflict, conflict!.ErrorCode);
                var current = await ApiAssert.Data<UserRolesResponse>(admin.GetAsync(url));
                Assert.Equal(winner!.Data!.Roles, current.Roles);
                Assert.Single(current.Roles);
                Assert.Equal(winner.Data.Version, current.Version);
            }
            finally
            {
                foreach (var response in responses) response.Dispose();
            }
        }
    }

    private sealed class RoleWriteBarrier : SaveChangesInterceptor
    {
        public string? TargetUserId { get; set; }
        private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _arrivals;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (TargetUserId is not null && eventData.Context!.ChangeTracker.Entries<ApplicationUser>()
                .Any(entry => entry.Entity.Id == TargetUserId && entry.Property(user => user.ConcurrencyStamp).IsModified))
            {
                if (Interlocked.Increment(ref _arrivals) == 2) _ready.TrySetResult();
                await _ready.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
            }
            return result;
        }
    }
}
