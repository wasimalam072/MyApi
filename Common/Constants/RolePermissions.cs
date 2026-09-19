namespace MyApi.Common.Constants;

/// <summary>Default grants and permission limits for the three application roles.</summary>
public static class RolePermissions
{
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> Grants =
        new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [ApplicationRoles.Admin] = Array.AsReadOnly(new[]
            {
                Permissions.UsersCreate, Permissions.UsersDelete, Permissions.UsersUpdate, Permissions.UsersView
            }),
            [ApplicationRoles.Manager] = Array.AsReadOnly(new[]
            {
                Permissions.UsersCreate, Permissions.UsersUpdate, Permissions.UsersView
            }),
            [ApplicationRoles.User] = Array.AsReadOnly(new[]
            {
                Permissions.UsersUpdate, Permissions.UsersView
            })
        };

    public static IReadOnlyList<string> ForRole(string role) => Grants.GetValueOrDefault(role) ?? [];

    public static string[] ForRoles(IEnumerable<string> roles) => roles
        .SelectMany(ForRole)
        .Distinct(StringComparer.Ordinal)
        .OrderBy(permission => permission, StringComparer.Ordinal)
        .ToArray();

    /// <summary>Legacy direct or role claims cannot exceed the account's current role privileges.</summary>
    public static string[] Constrain(IEnumerable<string> permissions, IEnumerable<string> roles)
    {
        var granted = permissions.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return ForRoles(roles).Where(granted.Contains).ToArray();
    }
}
