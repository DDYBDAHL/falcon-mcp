"""
Examples for using the User Management module with falcon-mcp

These examples demonstrate common user management operations:
1. Listing users with filters
2. Retrieving user details
3. Managing user roles
4. Auditing user accounts
"""

import os
from falcon_mcp.client import FalconClient
from falcon_mcp.modules.user_management import UserManagementModule

# Initialize the client
client_id = os.environ.get("FALCON_CLIENT_ID")
client_secret = os.environ.get("FALCON_CLIENT_SECRET")
base_url = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")

print("Initializing Falcon API Client...")
falcon_client = FalconClient(
    client_id=client_id,
    client_secret=client_secret,
    base_url=base_url,
)

if not falcon_client.authenticate():
    print("Failed to authenticate with Falcon API")
    exit(1)

print("✓ Successfully authenticated\n")

# Initialize the User Management module
user_mgmt = UserManagementModule(falcon_client)

# Example 1: Query all active users
print("="*60)
print("Example 1: List Active Users")
print("="*60)
try:
    # Query for active users
    print("Querying for active users...")
    active_users = user_mgmt.query_users(
        filter="status:'active'",
        limit=10,
        sort="first_name.asc"
    )
    
    print(f"Found {len(active_users) if isinstance(active_users, list) else 0} active users")
    
    if active_users and not isinstance(active_users, dict):
        print(f"User UUIDs: {active_users[:3]}...")  # Print first 3
except Exception as e:
    print(f"Error: {e}")

print()

# Example 2: Find user by email
print("="*60)
print("Example 2: Find User by Email")
print("="*60)
try:
    # Note: Replace with an actual user email in your organization
    test_email = "test@example.com"
    print(f"Searching for user: {test_email}")
    
    user_info = user_mgmt.retrieve_user_by_email(email=test_email)
    
    if user_info and not isinstance(user_info, dict):
        for user in user_info:
            print(f"Found user:")
            print(f"  - Name: {user.get('name')}")
            print(f"  - UID: {user.get('uid')}")
            print(f"  - UUID: {user.get('uuid')}")
    else:
        print(f"User not found or error: {user_info}")
except Exception as e:
    print(f"Error: {e}")

print()

# Example 3: Get available roles
print("="*60)
print("Example 3: List Available Roles")
print("="*60)
try:
    print("Retrieving available role IDs...")
    
    roles = user_mgmt.get_available_role_ids()
    
    if roles and not isinstance(roles, dict):
        print(f"Found {len(roles)} available roles")
        print(f"Sample roles: {roles[:5]}")
    else:
        print(f"Error or no roles found: {roles}")
except Exception as e:
    print(f"Error: {e}")

print()

# Example 4: Get user details and roles
print("="*60)
print("Example 4: Get User Details and Roles")
print("="*60)
try:
    # First, query for users
    print("Querying for users...")
    user_uuids = user_mgmt.query_users(limit=1)  # Get first user
    
    if user_uuids and not isinstance(user_uuids, dict) and len(user_uuids) > 0:
        print(f"Retrieved {len(user_uuids)} user UUID(s)")
        
        # Get details for first user
        user_uuid = user_uuids[0]
        print(f"\nGetting details for user: {user_uuid}")
        
        user_details = user_mgmt.retrieve_users(ids=[user_uuid])
        
        if user_details and not isinstance(user_details, dict):
            for user in user_details:
                print(f"User Details:")
                print(f"  - Name: {user.get('name')}")
                print(f"  - UID: {user.get('uid')}")
                print(f"  - UUID: {user.get('uuid')}")
        
        # Get user roles
        print(f"\nGetting roles for user: {user_uuid}")
        user_roles = user_mgmt.get_user_roles(user_uuid=user_uuid)
        
        if user_roles and not isinstance(user_roles, dict):
            print(f"User has {len(user_roles)} role(s)")
            for role in user_roles:
                print(f"  - Role: {role.get('role_name')} (ID: {role.get('role_id')})")
    else:
        print("No users found")
except Exception as e:
    print(f"Error: {e}")

print()

# Example 5: Query with advanced FQL filters
print("="*60)
print("Example 5: Advanced FQL Queries")
print("="*60)
try:
    # Query users from a specific domain
    print("Querying users from corporate domain...")
    corp_users = user_mgmt.query_users(
        filter="uid:'*@corp.com'",
        limit=5
    )
    
    if corp_users and not isinstance(corp_users, dict):
        print(f"Found {len(corp_users)} users from corp.com domain")
    else:
        print(f"No users found or error: {corp_users}")
    
    # Query users by first name
    print("\nQuerying users with first name starting with 'John'...")
    john_users = user_mgmt.query_users(
        filter="first_name:'John*'",
        limit=5
    )
    
    if john_users and not isinstance(john_users, dict):
        print(f"Found {len(john_users)} users named John*")
    else:
        print(f"No users found or error: {john_users}")
        
except Exception as e:
    print(f"Error: {e}")

print()
print("="*60)
print("Examples completed!")
print("="*60)
