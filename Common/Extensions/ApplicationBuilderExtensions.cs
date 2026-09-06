namespace MyApi.Common.Extensions;

/// <summary>
/// Contains configuration for the HTTP request pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Configures middleware used by the Web API.
    ///
    /// Middleware order is important:
    /// exception handling comes first, followed by transport/security,
    /// API-key protection, authentication, and authorization.
    /// </summary>
    public static WebApplication UseApiPipeline(
        this WebApplication app)
    {
        // Handles exceptions thrown by middleware and controllers.
        app.UseExceptionHandler();

        if (!app.Environment.IsDevelopment())
        {
            // Adds HTTP Strict Transport Security headers
            // when running outside development.
            app.UseHsts();
        }

        ConfigureSwagger(app);

        app.UseSerilogRequestLogging(
            options =>
            {
                options.MessageTemplate =
                    "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";

                options.EnrichDiagnosticContext =
                    (
                        diagnosticContext,
                        httpContext) =>
                    {
                        diagnosticContext.Set(
                            "TraceId",
                            Activity.Current?.Id
                            ?? httpContext.TraceIdentifier);

                        diagnosticContext.Set(
                            "RequestHost",
                            httpContext.Request.Host.Value);
                    };
            });

        app.UseHttpsRedirection();

        // API-key validation happens before JWT authentication.
        // This protects even anonymous API endpoints such as login.
        app.UseMiddleware<ApiKeyMiddleware>();

        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllers();

        ConfigureRootEndpoint(app);

        return app;
    }

    private static void ConfigureSwagger(
        WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            return;
        }

        app.UseSwagger();

        app.UseSwaggerUI(
            options =>
            {
                IApiVersionDescriptionProvider provider =
                    app.Services
                        .GetRequiredService<
                            IApiVersionDescriptionProvider>();

                foreach (
                    ApiVersionDescription description
                    in provider.ApiVersionDescriptions)
                {
                    options.SwaggerEndpoint(
                        $"/swagger/{description.GroupName}/swagger.json",
                        description.GroupName
                            .ToUpperInvariant());
                }
            });
    }

    private static void ConfigureRootEndpoint(
        WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.MapGet(
                "/",
                () => Results.Redirect(
                    "/swagger"));

            return;
        }

        app.MapGet(
            "/",
            () => Results.Ok(
                new
                {
                    application = "MyApi",
                    status = "Running"
                }));
    }
}