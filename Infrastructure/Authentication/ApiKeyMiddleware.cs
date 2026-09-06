namespace MyApi.Infrastructure.Authentication;

/// <summary>
/// Validates the API key for every API request.
///
/// This protection is independent from JWT authentication.
/// Therefore anonymous endpoints such as login can still require
/// the application's API key.
/// </summary>
public sealed class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApiKeyMiddleware> _logger;

    public ApiKeyMiddleware(
        RequestDelegate next,
        ILogger<ApiKeyMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IOptions<ApiKeySettings> options)
    {
        // Swagger, health checks and non-API endpoints
        // should not require the application API key.
        if (!context.Request.Path.StartsWithSegments("/api"))
        {
            await _next(context);
            return;
        }

        ApiKeySettings settings =
            options.Value;

        // Configuration validation should normally catch this
        // during application startup. This check remains as
        // defense-in-depth protection.
        if (string.IsNullOrWhiteSpace(settings.Key))
        {
            throw new InvalidOperationException(
                "API-key authentication has not been configured.");
        }

        if (!context.Request.Headers.TryGetValue(
                settings.HeaderName,
                out var suppliedApiKey))
        {
            await WriteUnauthorizedAsync(
                context,
                "API key is required.");

            return;
        }

        if (!ApiKeysMatch(
                settings.Key,
                suppliedApiKey.ToString()))
        {
            _logger.LogWarning(
                "Request rejected because an invalid API key was supplied. Path={Path} TraceId={TraceId}",
                context.Request.Path,
                GetTraceId(context));

            await WriteUnauthorizedAsync(
                context,
                "The supplied API key is invalid.");

            return;
        }

        await _next(context);
    }

    /// <summary>
    /// Performs a fixed-time comparison to avoid revealing
    /// information through timing differences.
    /// </summary>
    private static bool ApiKeysMatch(
        string expected,
        string supplied)
    {
        byte[] expectedBytes =
            Encoding.UTF8.GetBytes(expected);

        byte[] suppliedBytes =
            Encoding.UTF8.GetBytes(supplied);

        return expectedBytes.Length == suppliedBytes.Length
               && CryptographicOperations.FixedTimeEquals(
                   expectedBytes,
                   suppliedBytes);
    }

    private static async Task WriteUnauthorizedAsync(
        HttpContext context,
        string message)
    {
        string traceId =
            GetTraceId(context);

        ApiResponse<object> response =
            ApiResponse<object>.CreateFailure(
                StatusCodes.Status401Unauthorized,
                message,
                ErrorCodes.Authentication.InvalidApiKey,
                traceId);

        context.Response.StatusCode =
            response.StatusCode;

        context.Response.ContentType =
            "application/json";

        await context.Response.WriteAsJsonAsync(
            response,
            context.RequestAborted);
    }

    private static string GetTraceId(
        HttpContext context)
    {
        return Activity.Current?.Id
               ?? context.TraceIdentifier;
    }
}