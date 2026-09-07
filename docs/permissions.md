# User permissions

Admin and Manager accounts can assign and edit direct permissions for registered
users. Users perform management actions according to their effective permissions:
the union of direct grants and permissions inherited from their roles.

## Endpoints

All requests need the configured `ApiKey` header. Authenticated requests also
need `Authorization: Bearer <access-token>`.

| Method | URL | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/permissions` | Admin or Manager | List assignable names and descriptions |
| GET | `/api/v1/permissions/users/{userId}` | Admin or Manager | Read a user's grants, role permissions, and version |
| PUT | `/api/v1/permissions/users/{userId}` | Admin or Manager | Replace the user's direct grants |
| GET | `/api/v1/permissions/me` | Any authenticated user | Read the caller's current permissions |

## Assign or edit permissions

1. Log in as an Admin or Manager through `POST /api/v1/auth/login`.
2. Get the target user's permissions with `GET /api/v1/permissions/users/{userId}`.
3. Copy `data.version` into the update request and supply the complete desired set:

```http
PUT /api/v1/permissions/users/<registered-user-id>
Authorization: Bearer <admin-or-manager-token>
ApiKey: <configured-api-key>
Content-Type: application/json

{
  "version": "<version-from-the-GET-response>",
  "permissions": ["Users.View", "Users.Update"]
}
```

This replaces the user's direct grants. Omitting a previously assigned name
revokes that direct grant. Send `"permissions": []` to revoke all direct grants.
Permission names are trimmed, matched without case sensitivity, converted to
their canonical spelling, and deduplicated. Unknown, null, or blank names are
rejected. Omitting the list is an error and never clears permissions implicitly.

The response uses the existing `ApiResponse<T>` envelope. For example:

```json
{
  "statusCode": 200,
  "success": true,
  "message": "User permissions saved. Changes apply to the next authenticated request.",
  "data": {
    "userId": "<registered-user-id>",
    "fullName": "Example User",
    "email": "user@example.com",
    "roles": ["User"],
    "assignedPermissions": ["Users.Update", "Users.View"],
    "inheritedPermissions": [],
    "effectivePermissions": ["Users.Update", "Users.View"],
    "version": "<new-version>"
  },
  "traceId": "<request-trace-id>",
  "timestampUtc": "2026-09-07T10:00:00Z"
}
```

Use the latest returned `version` for each subsequent edit. A stale version
returns `409` with `PERMISSIONS_CONFLICT`; retrieve the latest state and reconcile
the changes before retrying. Identity profile or account changes can also change
this version. Claim removals, additions, and the version update are saved together
in one database transaction. The API logs successful edits with the acting user,
target user, assigned permissions, and request trace ID.

## What users can do

| Permission | Protected management endpoint |
| --- | --- |
| `Users.View` | `GET /api/v1/adminusers/AllRegisteredUsers` |
| `Users.Create` | `POST /api/v1/adminusers/CreateUser` |
| `Users.Update` | `PUT /api/v1/adminusers/UpdateUser/{userId}` |
| `Users.Delete` | `DELETE /api/v1/adminusers/DeleteUser/{userId}` |

`CreateUser` accepts `RegisterRequest` and creates a standard User account.
`UpdateUser` accepts `UpdateUserRequest` (`fullName` and `phoneNumber`). These
management permissions apply to registered accounts; they do not grant the Admin
or Manager role or permission-delegation rights. Only Admin and Manager roles
can call the permission-management endpoints, even if a normal user has all four
management permissions.

Public self-registration and the logged-in user's own profile endpoints retain
their existing access rules. Management permissions govern the endpoints in the
table above.

## Active sessions and inherited permissions

After JWT signature and lifetime validation, the API reloads the account's roles
and effective permissions from the database. Grants, revocations, and role
changes therefore apply to the next authenticated request using the same JWT.
Requests already authorized before an edit may finish. A deleted user's token is
rejected with `401`.

The encoded JWT contains a snapshot from login. For the current permissions in a
client application, call `GET /api/v1/permissions/me`. The API checks the refreshed
database state instead of trusting that old permission snapshot. This requires
database reads on authenticated requests; authorization data is not cached.

The edit endpoint changes direct user claims only. It preserves unrelated claims
and role memberships. A permission granted through a role remains effective when
its direct user grant is removed. In particular, seeded Admin accounts inherit
all four permissions. The response separates assigned and inherited grants so a
client can explain why access remains available.

No schema migration is required. The implementation uses the existing Identity
user-claim tables and user concurrency stamp.

## Validation and failures

- `400`: missing list/version, invalid permission selection, or invalid user ID.
- `401`: missing/invalid authentication, invalid API key, or a deleted account.
- `403`: caller lacks the required role or action permission.
- `404`: the requested target user does not exist.
- `409`: another request changed the user after the supplied version was read.

## Tests

Run all unit and integration tests:

```sh
dotnet test MyApi.sln
```

The HTTP tests start the real API with an isolated SQLite database, generated
administrator credentials, and actual Identity/JWT authentication. Every test
disposes its database, including on assertion failure. They cover both Admin and
Manager delegation, all four protected actions, replacement and revocation with
old tokens, invalid requests, stale versions, preserved role/unrelated claims,
ordinary-user denial, role removal, and deleted accounts.

For SQL Server, set `MYAPI_TEST_SQLSERVER` to a connection string for a local or
dedicated test server and run:

```sh
dotnet test tests/MyApi.IntegrationTests/MyApi.IntegrationTests.csproj
```

Each SQL test creates a random `MyApi_PermissionTests_*` database, applies the
real migrations, and drops that database afterward. The database named in the
supplied connection string is never used. The test login needs create/drop
database permission. Forced process termination or an unavailable server may
require manual cleanup of these temporary databases.

The SQL-only concurrency test forces two edits to pass their initial version
checks together and verifies one succeeds, one returns `409`, and only the
winner's complete permission set persists. It is explicitly skipped when
`MYAPI_TEST_SQLSERVER` is unset.

The implementation uses the ASP.NET Core
[token-validation event](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.jwtbearer.jwtbearerevents?view=aspnetcore-10.0),
EF Core [atomic saves](https://learn.microsoft.com/en-us/ef/core/saving/transactions),
and [optimistic concurrency](https://learn.microsoft.com/en-us/ef/core/saving/concurrency).
