# User roles

The application uses the existing `Admin`, `Manager`, and `User` roles. Roles
are seeded at startup; this API assigns those roles to accounts.

| Role | Default permissions | Account access |
| --- | --- | --- |
| Admin | `Users.Create`, `Users.Delete`, `Users.Update`, `Users.View` | All accounts |
| Manager | `Users.Create`, `Users.Update`, `Users.View` | Create, view, and update accounts; cannot delete |
| User | `Users.Update`, `Users.View` | View and update only their own account |

Users access their own profile with `GET /api/v1/users/GetCurrentUser` and
`PUT /api/v1/users/UpdateUser`. These endpoints identify the account from the
authenticated token. Supplying another user's ID does not change the target.
The `/adminusers` endpoints require Admin or Manager; deletion requires Admin.

Startup reconciles permission claims for all three roles to this exact matrix,
including existing databases. No schema migration is required. Direct grants
cannot exceed the current role's permissions or expand a User's access to other
accounts. Accounts with several roles receive the union of their allowed grants.

| Acting role | Allowed role changes |
| --- | --- |
| Admin | Assign or remove any of the three roles, including appointing Managers |
| Manager | Assign or remove `User` on ordinary accounts or accounts without roles |
| User | Read their own roles; cannot change roles |

Managers cannot grant `Admin` or `Manager`, change their own roles, or edit the
roles of any account that has `Admin` or `Manager`, even if it also has `User`.
An Admin cannot remove their own `Admin` role through this API; another Admin
must make that change. Multiple roles per account are supported.

## Endpoints

All requests require the configured `ApiKey` header and
`Authorization: Bearer <access-token>`.

| Method | URL | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/roles` | Admin or Manager | List the three roles, their descriptions, and their permissions |
| GET | `/api/v1/roles/GetMyRoles` | Any authenticated user | Read your current roles, effective permissions, and version |
| GET | `/api/v1/roles/GetUserRoles/{userId}` | Admin or Manager | Read a user's roles, effective permissions, and version |
| PUT | `/api/v1/roles/UpdateUserRoles/{userId}` | Admin or Manager, subject to the hierarchy above | Replace the user's role memberships |

The role list includes a `permissions` array on each role, loaded from its
current permission claims. For example, the seeded Admin entry is:

```json
{
  "name": "Admin",
  "description": "Manage all user roles, appoint Managers, and administer users and permissions.",
  "permissions": ["Users.Create", "Users.Delete", "Users.Update", "Users.View"]
}
```

Roles with no permission claims return `"permissions": []`. The list does not
include direct user grants. Role-based access, such as a Manager's ability to
manage ordinary users' roles, is described separately from permission claims.

## Admin appoints a Manager

1. Sign in as an Admin using `POST /api/v1/auth/login`. The existing
   `InitialAdmin` configuration can bootstrap the first Admin at startup.
2. Select an existing account, or create one with
   `POST /api/v1/adminusers/CreateUser` using the usual registration fields.
   New accounts start with the `User` role.
3. Read `GET /api/v1/roles/GetUserRoles/{userId}` and copy `data.version`.
4. Submit the complete desired role set:

```http
PUT /api/v1/roles/UpdateUserRoles/<user-id>
Authorization: Bearer <admin-token>
ApiKey: <configured-api-key>
Content-Type: application/json

{
  "version": "<version-from-GET>",
  "roles": ["Manager", "User"]
}
```

Use `["User"]` to demote a Manager back to a standard account. Only an Admin can
make that change. A public registration request cannot choose privileged roles.

## Manager manages a user's role

Sign in as the appointed Manager, read the target user's role state, then send:

```http
PUT /api/v1/roles/UpdateUserRoles/<ordinary-user-id>
Authorization: Bearer <manager-token>
ApiKey: <configured-api-key>
Content-Type: application/json

{
  "version": "<version-from-GET>",
  "roles": ["User"]
}
```

This assigns `User` to an account without roles or keeps an existing `User`
membership. Send `"roles": []` to remove all roles on an ordinary account.
Removing roles does not disable login or delete stored direct permission grants,
but an account without roles has no effective permissions and cannot view or
update profiles until a role is assigned again.
Managers can manage ordinary accounts across the application; there is no
per-user Manager assignment in the data model.

The API responds using the existing `ApiResponse<T>` envelope:

```json
{
  "statusCode": 200,
  "success": true,
  "message": "User roles saved. Changes apply to the next authenticated request.",
  "data": {
    "userId": "<user-id>",
    "fullName": "Example User",
    "email": "user@example.com",
    "roles": ["User"],
    "permissions": ["Users.Update", "Users.View"],
    "version": "<current-version>"
  }
}
```

The actual response also includes the request trace ID and timestamp.
All user-role detail and update responses include `permissions`: the sorted,
deduplicated union of direct and inherited grants within the listed roles'
permission limits, consistent with login and profile responses. After a role
change, this field reflects the new role set. Legacy direct grants outside those
limits are ignored, including on existing JWTs. The permission-detail response
still reports stored direct grants in `assignedPermissions` for review or removal.

## Validation, sessions, and permissions

- `roles` is the complete desired set. Omitted roles are removed; an omitted or
  null array is rejected. Names are trimmed, matched without case sensitivity,
  converted to canonical spelling, and deduplicated. Custom roles are rejected.
- Send the latest returned `version` with each edit. Stale versions return
  `409 ROLES_CONFLICT`; read the current state and reconcile before retrying.
  Role, direct-permission, and Identity profile changes share the user version.
  Saving the same role set does not change the version.
- The user version and membership changes commit in one database transaction.
  A failed write rolls back both. Successful changes log the actor, target,
  assigned roles, and trace ID.
- Existing JWTs pick up role grants and revocations on the next authenticated
  request through the existing database-backed authorization refresh. Requests
  already authorized may finish. The encoded JWT still contains the login
  snapshot; clients should use `/api/v1/roles/GetMyRoles` for current roles.
- Role changes preserve stored direct permissions and unrelated claims. Effective
  permissions are recalculated within the new role's limits. The same permission
  names have different account scopes: a User's `Users.View` and `Users.Update`
  apply only to their own profile. See [user permissions](permissions.md).
- No schema migration or additional package is needed. The feature uses
  `AspNetUserRoles`, `AspNetRoles`, and the Identity user concurrency stamp.

Failures use `400` for invalid input, `401` for missing/invalid authentication,
`403` for role hierarchy violations, `404` for unknown users, and `409` for stale
edits. Role-specific codes are `ROLES_INVALID_SELECTION`,
`ROLES_VERSION_REQUIRED`, `ROLES_FORBIDDEN`, `ROLES_SELF_DEMOTION`, and
`ROLES_CONFLICT`. Model-validation failures use the existing
`ERR_VALIDATION_ERROR` code.

## Verification

```sh
dotnet test MyApi.sln
```

Integration tests use real Identity/JWT authentication and an isolated SQLite
database. They cover the Admin-to-Manager workflow, Manager role changes,
privilege restrictions, existing tokens, inherited and direct permissions,
invalid input, stale edits, transaction rollback, registration defaults,
profile ownership, legacy grants, and idempotent seeding of existing databases.

The SQL Server concurrency test requires `MYAPI_TEST_SQLSERVER` and uses the
same temporary-database setup described in [permissions.md](permissions.md).
It checks competing edits with identical and different role sets. Without that
configuration, it is explicitly skipped.

The implementation follows ASP.NET Core's
[role authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-10.0)
and EF Core's [transaction](https://learn.microsoft.com/en-us/ef/core/saving/transactions)
and [concurrency](https://learn.microsoft.com/en-us/ef/core/saving/concurrency) mechanisms.
