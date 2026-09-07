namespace MyApi.Common.Constants;

/// <summary>
/// Contains stable machine-readable API error codes.
///
/// Clients should depend on these codes instead of parsing
/// human-readable response messages.
/// </summary>
public static class ErrorCodes
{
    public static class Authentication
    {
        public const string UserIdMissing =
            "AUTH_USER_ID_MISSING";

        public const string InvalidCredentials =
            "AUTH_INVALID_CREDENTIALS";

        public const string AccountLocked =
            "AUTH_ACCOUNT_LOCKED";

        public const string AccountExists =
            "AUTH_ACCOUNT_EXISTS";

        public const string ConfigurationError =
            "AUTH_CONFIGURATION_ERROR";

        public const string RegistrationFailed = "AUTH_REGISTRATION_FAILED";

        public const string RoleAssignmentFailed = "AUTH_ROLE_ASSIGNMENT_FAILED";

        public const string InvalidApiKey =
            "INVALID_API_KEY";

        public const string Unauthorized =
            "UNAUTHORIZED";
    }

    public static class Users
    {
        public const string IdRequired =
            "USER_ID_REQUIRED";

        public const string NotFound =
            "USER_NOT_FOUND";

        public const string PhoneNumberAlreadyExists =
            "USER_PHONE_NUMBER_ALREADY_EXISTS";

        public const string UpdateFailed =
            "USER_UPDATE_FAILED";

        public const string DeleteFailed =
            "USER_DELETE_FAILED";
    }

    public static class General
    {
        public const string InternalServerError = "ERR_INTERNAL_SERVER_ERROR";
        public const string BadRequest = "ERR_BAD_REQUEST";
        public const string NotFound = "ERR_NOT_FOUND";
        public const string ValidationError = "ERR_VALIDATION_ERROR";
    }

    public static class Validation
    {
        public const string InvalidInput = "ERR_INVALID_INPUT";
    }
}
