using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MyApi.Data;
using MyApi.Models.Auth;

namespace MyApi.IntegrationTests;

internal sealed class PermissionApiFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection? _sqlite;
    private readonly string? _sqlServer;
    private readonly SaveChangesInterceptor? _interceptor;
    private bool _disposed;
    public string AdminEmail { get; } = $"admin-{Guid.NewGuid():N}@example.com";
    public string Password { get; } = $"Test-{Guid.NewGuid():N}-9!";
    private string ApiKey { get; } = Guid.NewGuid().ToString("N");

    private PermissionApiFactory(SaveChangesInterceptor? interceptor)
    {
        _interceptor = interceptor;
        string? configured = Environment.GetEnvironmentVariable("MYAPI_TEST_SQLSERVER");
        if (string.IsNullOrWhiteSpace(configured))
        {
            _sqlite = new SqliteConnection("Data Source=:memory:;Foreign Keys=True;Pooling=False");
        }
        else
        {
            _sqlServer = new SqlConnectionStringBuilder(configured)
            {
                InitialCatalog = $"MyApi_PermissionTests_{Guid.NewGuid():N}", Pooling = false
            }.ConnectionString;
        }
    }

    public static async Task<PermissionApiFactory> StartAsync(SaveChangesInterceptor? interceptor = null)
    {
        var factory = new PermissionApiFactory(interceptor);
        try
        {
            if (factory._sqlite is not null) await factory._sqlite.OpenAsync();
            await using (var database = factory.CreateDbContext())
            {
                if (factory._sqlite is not null) await database.Database.EnsureCreatedAsync();
                else await database.Database.MigrateAsync();
            }
            using var client = factory.Client();
            return factory;
        }
        catch
        {
            await factory.DisposeAsync();
            throw;
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["InitialAdmin:Email"] = AdminEmail,
                ["InitialAdmin:Password"] = Password,
                ["InitialAdmin:FullName"] = "Permission Test Administrator",
                ["ApiKeyAuthentication:Key"] = ApiKey,
                ["ApiKeyAuthentication:HeaderName"] = "ApiKey",
                ["Serilog:MinimumLevel:Default"] = "Error",
                ["Serilog:WriteTo:0:Name"] = "Console",
                ["Serilog:WriteTo:1:Name"] = "Console"
            }));
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ApplicationDbContext>();
            services.RemoveAll<DbContextOptions<ApplicationDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<ApplicationDbContext>>();
            services.AddDbContext<ApplicationDbContext>(ConfigureDatabase);
        });
    }

    private void ConfigureDatabase(DbContextOptionsBuilder options)
    {
        if (_sqlite is not null) options.UseSqlite(_sqlite);
        else options.UseSqlServer(_sqlServer);
        if (_interceptor is not null) options.AddInterceptors(_interceptor);
    }

    public ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>();
        ConfigureDatabase(options);
        return new ApplicationDbContext(options.Options);
    }

    public HttpClient Client(string? token = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = false
        });
        client.DefaultRequestHeaders.Add("ApiKey", ApiKey);
        if (token is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public RegisterRequest NewRegistration() => new()
    {
        Email = $"user-{Guid.NewGuid():N}@example.com", FullName = "Permission Test User",
        PhoneNumber = "+15555550101", Password = Password, ConfirmPassword = Password
    };

    public async Task<RegisterResponse> RegisterAsync()
    {
        using var client = Client();
        return await ApiAssert.Data<RegisterResponse>(client.PostAsJsonAsync("/api/v1/auth/register", NewRegistration()), HttpStatusCode.Created);
    }

    public async Task<HttpClient> LoginAsync(string email)
    {
        using var client = Client();
        var login = await ApiAssert.Data<LoginResponse>(client.PostAsJsonAsync("/api/v1/auth/login", new LoginRequest
        {
            Email = email, Password = Password
        }));
        return Client(login.AccessToken);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        try { await base.DisposeAsync(); }
        finally
        {
            if (_sqlite is not null) await _sqlite.DisposeAsync();
            else
            {
                await using var database = CreateDbContext();
                await database.Database.EnsureDeletedAsync();
            }
        }
    }
}

internal static class ApiAssert
{
    public static async Task<ApiResponse<T>> Response<T>(Task<HttpResponseMessage> request, HttpStatusCode status)
    {
        using var response = await request;
        string body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == status,
            $"{response.RequestMessage?.Method} {response.RequestMessage?.RequestUri?.AbsolutePath}: expected {(int)status}, got {(int)response.StatusCode}. {body}");
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var result = JsonSerializer.Deserialize<ApiResponse<T>>(body);
        Assert.NotNull(result);
        Assert.Equal((int)status, result.StatusCode);
        Assert.Equal(response.IsSuccessStatusCode, result.Success);
        Assert.False(string.IsNullOrWhiteSpace(result.TraceId));
        return result;
    }

    public static async Task<T> Data<T>(Task<HttpResponseMessage> request, HttpStatusCode status = HttpStatusCode.OK) where T : class
    {
        var response = await Response<T>(request, status);
        Assert.NotNull(response.Data);
        return response.Data;
    }
}
