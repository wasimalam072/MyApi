namespace MyApi.Common.Constants;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class ApiKeyAuthAttribute : Attribute, IAsyncActionFilter
{
    private const string ApiKeyHeaderName = "ApiKey";
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if(!context.HttpContext.Request.Headers.TryGetValue(ApiKeyHeaderName, out var potentialApiKey))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var configuration = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var apiKey = configuration.GetValue<string>("ApiKey");

        if(!apiKey.Equals(potentialApiKey))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        await next().ConfigureAwait(false);
    }
}