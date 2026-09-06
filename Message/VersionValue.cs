namespace MyApi.Message;

public static class VersionValue
{
    public const string Version_1 = "1.0";
    public const string Version_2 = "2.0";

    public static readonly IReadOnlyList<ApiVersionDefinition> All =
    [
        new("v1", Version_1, "ASP.NET Core Web API version 1"),
        new("v2", Version_2, "ASP.NET Core Web API version 2 ")
    ];
}

public sealed record ApiVersionDefinition(string GroupName, string Version, string Description);