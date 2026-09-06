namespace MyApi.Common.Constants;

public static class ApplicationRoles
{
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string User = "User";

    public static readonly IReadOnlyList<string> All =
    [
        Admin,
        Manager,
        User
    ];
}
