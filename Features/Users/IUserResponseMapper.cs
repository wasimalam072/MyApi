namespace MyApi.Features.Users;

public interface IUserResponseMapper
{
    Task<RegisteredUserResponse> MapAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default);
}