# User Management Module Implementation Guide

## Overview

This guide documents the implementation of user management capabilities in falcon-mcp. The User Management module has been added to the project following the established patterns and architectural conventions.

## What Was Added

### New Files

1. **`falcon_mcp/modules/user_management.py`** (13.5 KB)
   - Complete User Management module implementation
   - Provides 8 tools for user search, retrieval, and role management
   - Includes FQL documentation resources
   - Follows established BaseModule pattern

2. **`docs/USER_MANAGEMENT.md`** (6.2 KB)
   - Comprehensive documentation of all tools and operations
   - FQL query examples and syntax guide
   - Use cases and practical examples
   - Error handling and rate limiting information

3. **`examples/user_management_example.py`** (5.2 KB)
   - Real-world usage examples
   - Demonstrates all major operations
   - Ready-to-run example script

## Architecture & Design Patterns

### Module Discovery

The falcon-mcp system uses automatic module discovery via the registry:

```python
# In falcon_mcp/registry.py
for _, name, is_pkg in pkgutil.iter_modules([modules_path]):
    if not is_pkg and name != "base":
        # Look for *Module classes
        for attr_name in dir(module):
            if attr_name.endswith("Module") and attr_name != "BaseModule":
                module_name = attr_name.lower().replace("module", "")
                AVAILABLE_MODULES[module_name] = module_class
```

**Result:** Your `UserManagementModule` class is automatically discovered and registered as the `usermanagement` module.

### Tool Registration Pattern

Each module follows a consistent pattern:

```python
class UserManagementModule(BaseModule):
    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(server, self.query_users, "query_users")
        # Tools are automatically prefixed with "falcon_"
        # Result: "falcon_query_users" tool
    
    def register_resources(self, server: FastMCP) -> None:
        # Register FQL documentation as resources
        fql_resource = TextResource(
            uri=AnyUrl("falcon://user-management/query/fql-guide"),
            ...
        )
        self._add_resource(server, fql_resource)
```

### API Integration Pattern

The module leverages base helper methods for consistent API interaction:

```python
# BaseModule provides these methods:

# For search-style operations returning filtered lists
self._base_search_api_call(
    operation="queryUserV1",
    search_params={"filter": filter, "limit": limit},
    error_message="Failed to query users"
)

# For operations with both query and body parameters
self._base_query_api_call(
    operation="CombinedUserRolesV2",
    query_params={"user_uuid": user_uuid},
    body_params={"roleIds": role_ids}
)
```

## Available Tools

### User Operations

| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `falcon_query_users` | Find users with FQL filter | filter, limit, offset, sort | List of user UUIDs |
| `falcon_retrieve_users` | Get details for user UUIDs | ids | List of user objects |
| `falcon_retrieve_user_by_email` | Find user by email (convenience) | email | User object |

### Role Operations

| Tool | Purpose | Input | Output |
|------|---------|-------|--------|
| `falcon_get_available_role_ids` | List all roles | none | List of role IDs |
| `falcon_get_roles` | Get role details | ids | List of role objects |
| `falcon_get_user_roles` | Get user's assigned roles | user_uuid, cid | User role assignments |
| `falcon_grant_user_role_ids` | Assign roles to user | user_uuid, role_ids | Operation result |
| `falcon_revoke_user_role_ids` | Remove roles from user | user_uuid, role_ids | Operation result |

## Integration with Existing Modules

The User Management module integrates seamlessly with other modules:

### Enabling the Module

**Default behavior (all modules enabled):**
```bash
falcon-mcp
```

**Select specific modules:**
```bash
falcon-mcp --modules detections,incidents,usermanagement
```

**Environment variable:**
```bash
export FALCON_MCP_MODULES="detections,incidents,usermanagement"
falcon-mcp
```

### Combined Workflows

You can now combine user management with other modules:

```python
# Find users affected by detections
detections = falcon_search_detections(filter="...")
for detection in detections:
    user_email = detection.get('user_email')
    user = falcon_retrieve_user_by_email(email=user_email)
```

## FQL Filtering Guide

The module includes comprehensive FQL documentation as resources:

### Available in MCP Tools
```
falcon://user-management/query/fql-guide
falcon://user-management/roles/fql-guide
```

### Common Filters

| Use Case | FQL Filter |
|----------|------------|
| Find admins | `uid:'admin*' OR first_name:'admin'` |
| Active users only | `status:'active'` |
| Users from domain | `uid:'*@example.com'` |
| Specific name | `first_name:'John' AND last_name:'Smith'` |
| Users with temp roles | `has_temporary_roles:'true'` |

## Implementation Details

### Dependencies

The module uses the existing falcon-mcp infrastructure:
- `FalconClient` - API communication
- `BaseModule` - Module base class
- `FastMCP` - MCP server integration
- FalconPy SDK (via FalconClient) - CrowdStrike API bindings

### API Operations Mapped

The module maps to these FalconPy operations:

| Tool | FalconPy Operation |
|------|--------------------|
| query_users | queryUserV1 |
| retrieve_users | retrieveUsersGETV1 |
| get_user_roles | CombinedUserRolesV2 |
| get_available_role_ids | GetAvailableRoleIds |
| get_roles | GetRoles |
| grant_user_role_ids | GrantUserRoleIds |
| revoke_user_role_ids | RevokeUserRoleIds |

### Error Handling

All tools include standardized error handling via `BaseModule` methods:

```python
response = self._base_search_api_call(...)
if self._is_error(response):
    return [{"error": response.get("error")}]
```

## Testing the Implementation

### 1. Verify Module Discovery

```bash
falcon-mcp --modules usermanagement
```

Should list:
```
Initialized 1 module with 8 tools and 2 resources
```

### 2. Run Example Script

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
python examples/user_management_example.py
```

### 3. Test with MCP Client

```python
# In Claude or MCP client
# List available tools
List all tools available

# Find active users
Use falcon_query_users to find all active users

# Get user details
Use falcon_retrieve_user_by_email to find user@example.com
```

## Contributing Improvements

### Adding Additional Tools

To add more user management operations:

1. Add method to `UserManagementModule` class
2. Register with `self._add_tool(server, self.method_name, "method_name")`
3. Use existing helper methods from `BaseModule`
4. Add documentation to `docs/USER_MANAGEMENT.md`

### Example: Add Create User Operation

```python
def create_user(
    self,
    username: str = Field(description="User email/username"),
    first_name: str = Field(description="First name"),
    last_name: str = Field(description="Last name"),
) -> Dict[str, Any]:
    """Create a new user."""
    return self._base_query_api_call(
        operation="createUserV1",
        body_params={
            "uid": username,
            "firstName": first_name,
            "lastName": last_name,
        },
        error_message="Failed to create user",
    )
```

## API Credentials & Scopes

Ensure your CrowdStrike API client has these scopes:

```
User Management:read       # For queries and retrievals
User Management:write      # For role grants/revokes
```

## Performance Considerations

### Pagination

The module supports paginated queries:

```python
# Query in batches of 100
users = falcon_query_users(
    filter="status:'active'",
    limit=100,
    offset=0  # or 100, 200, 300... for subsequent pages
)
```

### Batch Operations

Retrieve multiple users efficiently:

```python
# Get details for up to 500 users at once
users = falcon_retrieve_users(ids=user_uuid_list)
```

## Security Best Practices

1. **Never hardcode credentials** - Use environment variables
2. **Rotate API credentials regularly** - From CrowdStrike console
3. **Scope API clients** - Only enable required permissions
4. **Log operations** - Module logs to DEBUG level by default
5. **Validate user inputs** - Pydantic Field validation in place

## Troubleshooting

### Module Not Discovered

**Issue:** `falcon_query_users` tool not available

**Solution:**
1. Verify file is at `falcon_mcp/modules/user_management.py`
2. Check class name is `UserManagementModule` (ends with "Module")
3. Restart the server
4. Check logs: `falcon-mcp --debug`

### Authentication Failures

**Issue:** "Failed to authenticate with the Falcon API"

**Solution:**
1. Verify `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET`
2. Check `FALCON_BASE_URL` matches your region
3. Verify API credentials are active in CrowdStrike console
4. Check API client has required scopes

### FQL Query Errors

**Issue:** "Search operation failed" with FQL filters

**Solution:**
1. Check filter syntax using FQL guide resource
2. Verify field names are correct
3. Test filter in CrowdStrike console first
4. Use simpler filters to isolate issues

## Next Steps

1. **Test the implementation** - Run the example script
2. **Integrate with your workflows** - Use tools in MCP clients
3. **Consider contributing** - Submit improvements via GitHub
4. **Monitor performance** - Check API usage in CrowdStrike console

## References

- [FalconPy User Management](https://www.falconpy.io/Service-Collections/User-Management.html)
- [CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation/)
- [falcon-mcp Repository](https://github.com/CrowdStrike/falcon-mcp)
- [Falcon Query Language (FQL) Guide](https://falcon.crowdstrike.com/documentation/)

## License

This implementation follows the same MIT License as the falcon-mcp project.
