namespace MyApi.Common.Exceptions;

/// <summary>
/// Converts unexpected application exceptions into the
/// API's standard error-response format.
/// 
/// Exception details are logged internally but are never
/// returned to the client.
/// </summary>
public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(
        ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        string traceId =
            Activity.Current?.Id
            ?? httpContext.TraceIdentifier;

        _logger.LogError(
            exception,
            "Unhandled API exception. TraceId={TraceId}",
            traceId);

        ApiResponse<object> response =
            ApiResponse<object>.CreateFailure(
                StatusCodes.Status500InternalServerError,
                "Something went wrong while processing your request. Please try again later.",
                ErrorCodes.General.InternalServerError,
                traceId);

        httpContext.Response.StatusCode =
            response.StatusCode;

        httpContext.Response.ContentType =
            "application/json";

        await httpContext.Response.WriteAsJsonAsync(
            response,
            cancellationToken);

        return true;
    }
}