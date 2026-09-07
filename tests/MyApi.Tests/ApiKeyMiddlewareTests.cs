using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MyApi.Common.Constants;
using MyApi.Infrastructure.Authentication;

namespace MyApi.Tests;

public sealed class ApiKeyMiddlewareTests
{
    [Theory]
    [InlineData("/api/v1/auth/login", null, false)]
    [InlineData("/api/v1/auth/register", "wrong-key", false)]
    [InlineData("/api/v1/auth/login", "test-api-key", true)]
    [InlineData("/", null, true)]
    public async Task Middleware_enforces_the_configured_key_on_api_endpoints(string path, string? key, bool expectedNext)
    {
        bool nextCalled = false;
        var middleware = new ApiKeyMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, NullLogger<ApiKeyMiddleware>.Instance);
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        if (key is not null) context.Request.Headers["Test-Key"] = key;
        using var body = new MemoryStream();
        context.Response.Body = body;

        await middleware.InvokeAsync(context, Options.Create(new ApiKeySettings
        {
            HeaderName = "Test-Key", Key = "test-api-key"
        }));

        Assert.Equal(expectedNext, nextCalled);
        if (!expectedNext)
        {
            Assert.Equal(401, context.Response.StatusCode);
            body.Position = 0;
            var response = await JsonSerializer.DeserializeAsync<ApiResponse<object>>(body);
            Assert.Equal(ErrorCodes.Authentication.InvalidApiKey, response!.ErrorCode);
        }
    }
}
