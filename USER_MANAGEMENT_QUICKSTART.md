# User Management Module - Quick Start Guide

## Installation

The User Management module is already included in your fork. Just ensure you have the required API scopes configured.

## Enable the Module

### Option 1: Include with All Modules (Default)
```bash
falcon-mcp
```

### Option 2: Enable Only User Management
```bash
falcon-mcp --modules usermanagement
```

### Option 3: Enable Multiple Specific Modules
```bash
falcon-mcp --modules detections,incidents,usermanagement
```

### Option 4: Environment Variable
```bash
export FALCON_MCP_MODULES="usermanagement"
falcon-mcp
```

## Available Tools

Once enabled, you have access to these `falcon_*` tools:

### User Search & Retrieval
1. **`falcon_query_users`** - Search users with FQL filters
2. **`falcon_retrieve_users`** - Get details for user UUIDs
3. **`falcon_retrieve_user_by_email`** - Find user by email (convenience)

### Role Management
4. **`falcon_get_available_role_ids`** - List all roles
5. **`falcon_get_roles`** - Get role details
6. **`falcon_get_user_roles`** - Get user's roles
7. **`falcon_grant_user_role_ids`** - Assign roles to user
8. **`falcon_revoke_user_role_ids`** - Remove roles from user

## Quick Examples

### Example 1: Find Active Users

**Using with Claude or MCP Client:**
```
Find all active users in my Falcon environment using FQL
```

**Using Directly:**
```python
from falcon_mcp.modules.user_management import UserManagementModule

# Query active users
users = user_mgmt.query_users(filter="status:'active'", limit=10)
```

### Example 2: Find User by Email

**In MCP Client:**
```
Find the user with email admin@example.com
```

**Direct API:**
```python
user = user_mgmt.retrieve_user_by_email(email="admin@example.com")
```

### Example 3: Get User Roles

**In MCP Client:**
```
Get the roles assigned to user with UUID abc123xyz
```

**Direct API:**
```python
roles = user_mgmt.get_user_roles(user_uuid="abc123xyz")
```

### Example 4: Assign Roles to User

**In MCP Client:**
```
Grant the admin and analyst roles to user UUID abc123xyz
```

**Direct API:**
```python
result = user_mgmt.grant_user_role_ids(
    user_uuid="abc123xyz",
    role_ids=["admin-role-id", "analyst-role-id"]
)
```

## Common FQL Filters

| Task | FQL Filter |
|------|------------|
| Find all active users | `status:'active'` |
| Find user by email | `uid:'user@example.com'` |
| Find users from domain | `uid:'*@example.com'` |
| Find users by first name | `first_name:'John*'` |
| Find admin users | `uid:'admin*' OR first_name:'admin'` |
| Complex: Active and from domain | `status:'active' AND uid:'*@corp.com'` |

## Get Help with FQL

When using with MCP tools, access the FQL guide:

```
falcon://user-management/query/fql-guide
```

This provides:
- All available filter fields
- Syntax examples
- Sorting options
- Common use cases

## Workflow Example: Audit All Users

```python
# 1. Query all users
all_users = user_mgmt.query_users(
    filter="status:'active'",
    limit=500  # Max per query
)

# 2. Get details for all users
user_details = user_mgmt.retrieve_users(ids=all_users)

# 3. For each user, get their roles
for user in user_details:
    user_uuid = user['uuid']
    roles = user_mgmt.get_user_roles(user_uuid=user_uuid)
    print(f"{user['name']}: {roles}")
```

## Required API Scopes

Ensure your CrowdStrike API client has these scopes:

✓ `User Management:read` - For queries and retrievals
✓ `User Management:write` - For role assignments/revocations (optional)

## Troubleshooting

### "Module not found" or tool not available

1. Restart the server
2. Verify `UserManagementModule` is in `falcon_mcp/modules/user_management.py`
3. Run with debug: `falcon-mcp --debug`

### "Authentication failed"

1. Check `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` environment variables
2. Verify API credentials in CrowdStrike console
3. Check API scopes are enabled
4. Verify `FALCON_BASE_URL` matches your region

### "Search failed" or "No results"

1. Check FQL filter syntax using the guide resource
2. Try simpler filter: `status:'active'`
3. Verify users exist with that filter in Falcon console
4. Check API client permissions

## Next Steps

1. **Run the example:** `python examples/user_management_example.py`
2. **Read the docs:** See `docs/USER_MANAGEMENT.md` for detailed reference
3. **Check implementation:** See `IMPLEMENTATION_GUIDE.md` for architecture
4. **Integrate:** Use in your MCP clients or automation workflows

## Related Resources

- [Full Documentation](docs/USER_MANAGEMENT.md)
- [Implementation Guide](IMPLEMENTATION_GUIDE.md)
- [Example Script](examples/user_management_example.py)
- [FalconPy User Management](https://www.falconpy.io/Service-Collections/User-Management.html)
- [CrowdStrike API Docs](https://falcon.crowdstrike.com/documentation/)
