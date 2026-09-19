namespace MyApi.Common.Extensions;

/// <summary>
/// Contains dependency-injection configuration for the API.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all application and infrastructure services.
    /// </summary>
    public static IServiceCollection AddApiServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddControllers();

        services.AddApiExceptionHandling();

        services.AddApiValidation();

        services.AddDatabase(configuration);

        services.AddIdentityConfiguration();

        services.AddJwtAuthentication(
            configuration);

        services.AddApplicationAuthorization();

        services.AddApiVersioningConfiguration();

        services.AddSwaggerConfiguration();

        services.AddApiKeyAuthentication(
            configuration);

        services.AddApplicationServices();

        return services;
    }

    private static IServiceCollection AddApiExceptionHandling(
        this IServiceCollection services)
    {
        services.AddExceptionHandler<
            GlobalExceptionHandler>();

        services.AddProblemDetails();

        return services;
    }

    private static IServiceCollection AddApiValidation(
        this IServiceCollection services)
    {
        services.Configure<ApiBehaviorOptions>(
            options =>
            {
                options.InvalidModelStateResponseFactory =
                    context =>
                    {
                        IReadOnlyList<string> errors =
                            context.ModelState
                                .Where(entry =>
                                    entry.Value?.Errors.Count > 0)
                                .SelectMany(entry =>
                                    entry.Value!.Errors)
                                .Select(error =>
                                    error.ErrorMessage)
                                .Where(message =>
                                    !string.IsNullOrWhiteSpace(message))
                                .ToList();

                        string traceId =
                            Activity.Current?.Id
                            ?? context.HttpContext.TraceIdentifier;

                        ApiResponse<object> response =
                            ApiResponse<object>.CreateFailure(
                                StatusCodes.Status400BadRequest,
                                "Please check the information you entered.",
                                ErrorCodes.General.ValidationError,
                                traceId,
                                errors);

                        return new BadRequestObjectResult(
                            response);
                    };
            });

        return services;
    }

    private static IServiceCollection AddDatabase(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        string connectionString =
            configuration.GetConnectionString(
                "DefaultConnection")
            ?? throw new InvalidOperationException(
                "DefaultConnection was not configured.");

        services.AddDbContext<ApplicationDbContext>(
            options =>
            {
                options.UseSqlServer(
                    connectionString);
            });

        return services;
    }

    private static IServiceCollection AddIdentityConfiguration(
        this IServiceCollection services)
    {
        services.AddDataProtection();

        services
            .AddIdentityCore<ApplicationUser>(
                options =>
                {
                    options.User.RequireUniqueEmail =
                        true;

                    // Contact verification is optional until a confirmation workflow is available.
                    options.SignIn.RequireConfirmedEmail =
                        false;

                    options.SignIn.RequireConfirmedPhoneNumber =
                        false;

                    // Password requirements.
                    options.Password.RequiredLength =
                        8;

                    options.Password.RequireDigit =
                        true;

                    options.Password.RequireLowercase =
                        true;

                    options.Password.RequireUppercase =
                        true;

                    options.Password.RequireNonAlphanumeric =
                        true;

                    // Lock account after repeated failed attempts.
                    options.Lockout.AllowedForNewUsers =
                        true;

                    options.Lockout.MaxFailedAccessAttempts =
                        5;

                    options.Lockout.DefaultLockoutTimeSpan =
                        TimeSpan.FromMinutes(10);
                })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        return services;
    }

    private static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        IConfigurationSection jwtSection =
            configuration.GetSection(
                JwtSettings.SectionName);

        services
            .AddOptions<JwtSettings>()
            .Bind(jwtSection)
            .Validate(
                settings =>
                    !string.IsNullOrWhiteSpace(
                        settings.Key)
                    && settings.Key.Length >= 32,
                "JWT signing key must contain at least 32 characters.")
            .Validate(
                settings =>
                    !string.IsNullOrWhiteSpace(
                        settings.Issuer),
                "JWT issuer is required.")
            .Validate(
                settings =>
                    !string.IsNullOrWhiteSpace(
                        settings.Audience),
                "JWT audience is required.")
            .ValidateOnStart();

        JwtSettings jwtSettings =
            jwtSection.Get<JwtSettings>()
            ?? throw new InvalidOperationException(
                "JWT configuration was not found.");

        services
            .AddAuthentication(
                JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(
                options =>
                {
                    options.TokenValidationParameters =
                        new TokenValidationParameters
                        {
                            ValidateIssuer = true,

                            ValidIssuer =
                                jwtSettings.Issuer,

                            ValidateAudience = true,

                            ValidAudience =
                                jwtSettings.Audience,

                            ValidateIssuerSigningKey =
                                true,

                            IssuerSigningKey =
                                new SymmetricSecurityKey(
                                    Encoding.UTF8.GetBytes(
                                        jwtSettings.Key)),

                            ValidateLifetime = true,

                            ClockSkew =
                                TimeSpan.Zero,

                            NameClaimType =
                                ClaimTypes.NameIdentifier,

                            RoleClaimType =
                                ClaimTypes.Role
                        };

                    options.Events =
                        new JwtBearerEvents
                        {
                            OnTokenValidated = context => context.HttpContext.RequestServices
                                .GetRequiredService<CurrentUserAuthorization>().RefreshAsync(context),

                            OnChallenge =
                                async context =>
                                {
                                    context.HandleResponse();

                                    string traceId =
                                        Activity.Current?.Id
                                        ?? context.HttpContext
                                            .TraceIdentifier;

                                    ApiResponse<object> response =
                                        ApiResponse<object>
                                            .CreateFailure(
                                                StatusCodes
                                                    .Status401Unauthorized,
                                                "Your authentication session is invalid or has expired. Please sign in again.",
                                                ErrorCodes.Authentication
                                                    .Unauthorized,
                                                traceId);

                                    context.Response.StatusCode =
                                        response.StatusCode;

                                    context.Response.ContentType =
                                        "application/json";

                                    await context.Response
                                        .WriteAsJsonAsync(
                                            response);
                                }
                        };
                });

        return services;
    }

    private static IServiceCollection AddApplicationAuthorization(
        this IServiceCollection services)
    {
        services.AddAuthorization(
            options =>
            {
                foreach (string permission
                         in Permissions.All)
                {
                    options.AddPolicy(
                        permission,
                        policy =>
                        {
                            policy.RequireAuthenticatedUser();

                            policy.RequireClaim(
                                CustomClaimTypes.Permission,
                                permission);
                        });
                }
            });

        services.AddSingleton<
            IAuthorizationMiddlewareResultHandler,
            CustomAuthorizationMiddlewareResultHandler>();

        return services;
    }

    private static IServiceCollection AddApiKeyAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services
            .AddOptions<ApiKeySettings>()
            .Bind(
                configuration.GetSection(
                    ApiKeySettings.SectionName))
            .Validate(
                settings =>
                    !string.IsNullOrWhiteSpace(
                        settings.HeaderName),
                "API-key header name is required.")
            .Validate(
                settings =>
                    !string.IsNullOrWhiteSpace(
                        settings.Key),
                "API key is required.")
            .ValidateOnStart();

        return services;
    }

    private static IServiceCollection AddApplicationServices(
        this IServiceCollection services)
    {
        services.AddScoped<IUserPermissionService, UserPermissionService>();
        services.AddScoped<IUserRoleService, UserRoleService>();
        services.AddScoped<CurrentUserAuthorization>();

        services.AddScoped<
            IAuthService,
            AuthService>();

        services.AddScoped<
            ITokenService,
            TokenService>();

        services.AddScoped<
            IUserService,
            UserService>();

        services.AddScoped<
            IAdminUsersService,
            AdminUsersService>();    
            
        services.AddScoped<
            IUserResponseMapper,
            UserResponseMapper>();

        services.AddScoped<
            IPermissionService,
            PermissionService>();

        return services;
    }

    /// <summary>
    /// Configures URL-segment API versioning.
    ///
    /// Example:
    /// /api/v1/auth/login
    /// /api/v2/auth/login
    /// </summary>
    private static IServiceCollection AddApiVersioningConfiguration(
        this IServiceCollection services)
    {
        services.AddEndpointsApiExplorer();

        services.AddApiVersioning(options =>
        {
            // Adds supported and deprecated API versions
            // to response headers.
            options.ReportApiVersions = true;

            // When a version is not explicitly supplied,
            // ASP.NET Core uses the configured default version.
            options.AssumeDefaultVersionWhenUnspecified = true;

            options.DefaultApiVersion =
                new ApiVersion(1, 0);

            // API version is read from the URL:
            // /api/v1/...
            options.ApiVersionReader =
                new UrlSegmentApiVersionReader();

            // Keeps your custom versioning error format.
            options.ErrorResponses =
                new CustomApiVersioningError();
        });

        services.AddVersionedApiExplorer(options =>
        {
            // 1.0 -> v1
            // 2.0 -> v2
            options.GroupNameFormat =
                "'v'VVV";

            options.SubstituteApiVersionInUrl =
                true;
        });

        return services;
    }

    /// <summary>
    /// Configures Swagger/OpenAPI documentation for
    /// all supported API versions.
    /// </summary>
    private static IServiceCollection AddSwaggerConfiguration(
        this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            // Create one Swagger document for each API version.
            foreach (ApiVersionDefinition apiVersion
                     in VersionValue.All)
            {
                options.SwaggerDoc(
                    apiVersion.GroupName,
                    new OpenApiInfo
                    {
                        Title = "My API",
                        Version = apiVersion.Version,
                        Description = apiVersion.Description,

                        Contact = new OpenApiContact
                        {
                            Name = "Roshan Technology",
                            Email = "wasimalam072@gmail.com",
                            Url = new Uri(
                                "https://roshantechnology.com/")
                        }
                    });
            }

            // -----------------------------------------------------
            // JWT BEARER AUTHENTICATION
            // -----------------------------------------------------

            options.AddSecurityDefinition(
                "Bearer",
                new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,

                    Description =
                        "Enter the JWT access token only. " +
                        "Do not manually type the word Bearer."
                });

            // -----------------------------------------------------
            // API KEY AUTHENTICATION
            // -----------------------------------------------------

            options.AddSecurityDefinition(
                "ApiKey",
                new OpenApiSecurityScheme
                {
                    Name = "ApiKey",
                    Type = SecuritySchemeType.ApiKey,
                    In = ParameterLocation.Header,

                    Description =
                        "Enter the application API key."
                });

            // Apply both authentication definitions to Swagger.
            options.AddSecurityRequirement(document =>
                new OpenApiSecurityRequirement
                {
                    [
                        new OpenApiSecuritySchemeReference(
                            "Bearer",
                            document)
                    ] = [],

                    [
                        new OpenApiSecuritySchemeReference(
                            "ApiKey",
                            document)
                    ] = []
                });
        });

        return services;
    }
}
