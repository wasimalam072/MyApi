var builder =
    WebApplication.CreateBuilder(args);

builder.Host.UseSerilog(
    (context, services, configuration) =>
    {
        configuration
            .ReadFrom.Configuration(
                context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext();
    });

builder.Services.AddApiServices(builder.Configuration);

var app = builder.Build();

app.UseApiPipeline();

try
{
    Log.Information("Starting MyApi in {Environment}", app.Environment.EnvironmentName);

    if (app.Environment.IsDevelopment())
    {
        Log.Information("Running Development identity seeding.");

        await IdentitySeeder.SeedAsync(
            app.Services,
            app.Configuration);

        Log.Information("Identity initialization completed.");
    }

    await app.RunAsync();
}
catch (Exception exception)
{
    Log.Fatal(exception, "MyApi terminated unexpectedly.");
}
finally
{
    await Log.CloseAndFlushAsync();
}

// Lets integration tests host the real application.
public partial class Program { }
