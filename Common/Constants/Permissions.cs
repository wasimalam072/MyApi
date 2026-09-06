namespace MyApi.Common.Constants;

public static class Permissions
{
    public const string UsersView = "Users.View";
    public const string UsersCreate = "Users.Create";
    public const string UsersUpdate = "Users.Update";
    public const string UsersDelete = "Users.Delete";

    public static readonly IReadOnlyList<string> All = 
    [
        UsersView,
        UsersCreate,
        UsersUpdate,
        UsersDelete
    ];
}