namespace MyApi.Infrastructure.Authorization;

public sealed class CustomAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler
        _defaultHandler = new();

    private readonly ILogger<CustomAuthorizationMiddlewareResultHandler>
        _logger;

    public CustomAuthorizationMiddlewareResultHandler(
        ILogger<CustomAuthorizationMiddlewareResultHandler> logger)
    {
        _logger = logger;
    }

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        string traceId =
            Activity.Current?.Id
            ?? context.TraceIdentifier;

        // -------------------------------------------------------
        // 403 FORBIDDEN
        // Authenticated, but missing role / permission
        // -------------------------------------------------------

        if (authorizeResult.Forbidden)
        {
            _logger.LogWarning(
                "Authorization forbidden. Method={Method} Path={Path} TraceId={TraceId}",
                context.Request.Method,
                context.Request.Path.Value,
                traceId);

            context.Response.StatusCode =
                StatusCodes.Status403Forbidden;

            context.Response.ContentType =
                "application/json";

            var response = new ApiResponse<object>
            {
                StatusCode =
                    StatusCodes.Status403Forbidden,

                Message =
                    "You do not have permission to perform this action.",

                ErrorCode =
                    "AUTH_FORBIDDEN",

                TraceId =
                    traceId
            };

            await context.Response.WriteAsJsonAsync(response);

            return;
        }

        // -------------------------------------------------------
        // EVERYTHING ELSE
        // -------------------------------------------------------

        await _defaultHandler.HandleAsync(
            next,
            context,
            policy,
            authorizeResult);
    }
}