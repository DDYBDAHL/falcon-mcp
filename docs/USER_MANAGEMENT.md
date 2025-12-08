# User Management Module

The User Management module provides tools for accessing and managing CrowdStrike Falcon users, including user search, retrieval, and role management.

## API Credentials & Required Scopes

To use this module, ensure your CrowdStrike API client has the following scopes:

```
User Management:read
User Management:write (for role grants/revokes)
```

## Available Tools

### User Search & Retrieval

#### `falcon_query_users`
Query and list users in your CrowdStrike environment.

**Parameters:**
- `filter` (optional): FQL formatted filter string (see FQL guide below)
- `limit` (default: 10, max: 500): Maximum records to return
- `offset` (optional): Starting position for pagination
- `sort` (optional): Sort field and direction

**Returns:** List of user UUIDs matching the filter

**Example Usage:**
```python
# Find all active users
from falconpy import UserManagement

falcon = UserManagement(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
response = falcon.queryUserV1(filter="status:'active'")

# Find users by name
response = falcon.queryUserV1(filter="first_name:'John*'")

# Find users from a specific domain
response = falcon.queryUserV1(filter="uid:'*@example.com'")
```

#### `falcon_retrieve_users`
Retrieve detailed information for specified user UUIDs.

**Parameters:**
- `ids` (required): List of user UUIDs to retrieve

**Returns:** List of user objects with detailed information (name, UID, CID, etc.)

**Example Usage:**
```python
# Get details for specific users
response = falcon.retrieveUsersGETV1(ids=['uuid-1', 'uuid-2'])
```

#### `falcon_retrieve_user_by_email`
Convenience tool to find a user by email/username and return their full details.

**Parameters:**
- `email` (required): Email address or username to search for

**Returns:** User object with full details if found

**Example Usage:**
```python
# Find user by email in one call
response = falcon.retrieve_user_by_email(email='admin@example.com')
```

### Role Management

#### `falcon_get_available_role_ids`
List all available role IDs in your customer account.

**Returns:** List of available role IDs

**Example Usage:**
```python
# Get all available roles
response = falcon.get_available_role_ids()
```

#### `falcon_get_roles`
Retrieve detailed information for specified role IDs.

**Parameters:**
- `ids` (required): List of role IDs

**Returns:** List of role objects with permissions and descriptions

**Example Usage:**
```python
# Get role details
response = falcon.get_roles(ids=['role-id-1', 'role-id-2'])
```

#### `falcon_get_user_roles`
Retrieve roles assigned to a specific user.

**Parameters:**
- `user_uuid` (required): User UUID
- `cid` (optional): Customer ID to filter for
- `direct_only` (optional): Only return direct assignments

**Returns:** User's role assignments

**Example Usage:**
```python
# Get user's roles
response = falcon.get_user_roles(user_uuid='uuid-123')
```

#### `falcon_grant_user_role_ids`
Assign one or more roles to a user.

**Parameters:**
- `user_uuid` (required): User UUID
- `role_ids` (required): List of role IDs to assign

**Returns:** Operation result

**Example Usage:**
```python
# Grant roles to a user
response = falcon.grant_user_role_ids(
    user_uuid='uuid-123',
    role_ids=['role-id-1', 'role-id-2']
)
```

#### `falcon_revoke_user_role_ids`
Revoke one or more roles from a user.

**Parameters:**
- `user_uuid` (required): User UUID
- `role_ids` (required): List of role IDs to revoke

**Returns:** Operation result

**Example Usage:**
```python
# Revoke roles from a user
response = falcon.revoke_user_role_ids(
    user_uuid='uuid-123',
    role_ids=['role-id-1']
)
```

## FQL Query Examples

The User Management module supports Falcon Query Language (FQL) for advanced user searches.

### Common Searches

#### Find Active Users
```
status:'active'
```

#### Find All Admins
```
first_name:'admin' OR uid:'admin*'
```

#### Find Users in a Specific Domain
```
uid:'*@example.com'
```

#### Find Users by First Name (Wildcard)
```
first_name:'J*'
```

#### Combined Filters
```
status:'active' AND first_name:'John'
status:'active' AND (uid:'*@example.com' OR uid:'*@subsidiary.com')
```

### Sorting Results

```
# Sort by first name ascending
sort=first_name.asc

# Sort by UID descending
sort=uid.desc

# Alternative format
sort=first_name|desc
```

## Use Cases

### 1. Audit User Accounts
```python
# Find all active users and their roles
users = falcon.queryUserV1(filter="status:'active'")
for user_uuid in users:
    user_details = falcon.retrieveUsersGETV1(ids=[user_uuid])
    user_roles = falcon.get_user_roles(user_uuid=user_uuid)
    print(f"User: {user_details[0]['name']} - Roles: {user_roles}")
```

### 2. Onboard New User with Specific Roles
```python
# Find role IDs
available_roles = falcon.get_available_role_ids()

# Grant specific roles
falcon.grant_user_role_ids(
    user_uuid='new-user-uuid',
    role_ids=['analyst-role', 'viewer-role']
)
```

### n. Verify User Permissions
```python
# Check if a user has specific roles
user_roles = falcon.get_user_roles(user_uuid='user-uuid')
role_ids = [role['role_id'] for role in user_roles]

if 'admin-role' in role_ids:
    print("User is an admin")
```

### 4. Find Users by Email Domain
```python
# Find all users from corporate domain
users = falcon.queryUserV1(
    filter="uid:'*@corp.com'",
    limit=500
)
```

## Using with MCP Tools

When using this module with MCP-compatible tools (Claude, etc.), refer to the FQL guide resource:

```
falcon://user-management/query/fql-guide
```

This provides real-time documentation on building FQL filters.

## Error Handling

All tools return error objects with the following structure on failure:

```json
{
  "error": "Error message",
  "error_code": 1234
}
```

## Rate Limiting

Be aware of CrowdStrike API rate limits:
- User queries are typically limited to 500 results per page
- Use `offset` and `limit` parameters for pagination
- Implement exponential backoff for retries

## Related Documentation

- [FalconPy User Management](https://www.falconpy.io/Service-Collections/User-Management.html)
- [CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation/)
