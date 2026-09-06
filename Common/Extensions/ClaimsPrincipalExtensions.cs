namespace MyApi.Common.Constants.Extensions;

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Returns the authenticated application's user identifier.
    /// </summary>
    public static string? GetUserId(this ClaimsPrincipal user)
    {
        return user.FindFirstValue(ClaimTypes.NameIdentifier);
    }
}