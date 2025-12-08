"""
User Management module for Falcon MCP Server

This module provides tools for accessing and managing CrowdStrike Falcon users,
including user search, role management, and user information retrieval.
"""

from textwrap import dedent
from typing import Any, Dict, List, Optional

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

# FQL Guide for user queries
USER_SEARCH_FQL_DOCUMENTATION = dedent("""
    # User Search FQL Guide

    Use Falcon Query Language (FQL) to filter user searches. Here are the available fields:

    ## Available Filter Fields

    - **uid**: User ID (unique identifier)
    - **name**: User's display name
    - **first_name**: User's first name
    - **last_name**: User's last name
    - **status**: User status (active, inactive, disabled)
    - **assigned_cids**: Customer IDs the user is assigned to
    - **direct_assigned_cid**: Direct customer ID assignment
    - **temporarily_assigned_cids**: Temporary customer ID assignments
    - **has_temporary_roles**: Boolean indicating if user has temporary roles

    ## FQL Syntax Examples

    ### Basic Filters
    - `uid:'username@example.com'` - Find user by email/username
    - `first_name:'John'` - Find users by first name
    - `last_name:'Smith'` - Find users by last name
    - `name:'John Smith'` - Find users by full name
    - `status:'active'` - Find only active users

    ### Wildcard Searches
    - `first_name:'J*'` - Find users with first name starting with 'J'
    - `uid:'*@example.com'` - Find all users from a domain

    ### Combined Filters
    - `status:'active' AND first_name:'John'` - Active users named John
    - `status:'active' AND (first_name:'John' OR first_name:'Jane')`
    - `uid:'admin*'` - Find users with admin in their username

    ## Sort Fields

    Available sort fields for ordering results:
    - first_name
    - last_name
    - name
    - uid
    - has_temporary_roles

    Sort direction: use `.asc` or `.desc` suffix or `|asc` or `|desc` format
    Example: `first_name.asc` or `first_name|desc`

    ## Response Fields

    User search returns the user UUID. To get detailed user information, use
    the `falcon_retrieve_users` tool with the returned UUIDs.
""").strip()

ROLE_FQL_DOCUMENTATION = dedent("""
    # Role Query FQL Guide

    Use Falcon Query Language (FQL) to filter role queries.

    ## Available Filter Fields

    - **role_id**: The ID of the role
    - **role_name**: The human-readable name of the role

    ## FQL Syntax Examples

    - `role_name:'Admin'` - Find admin role
    - `role_id:'*'` - List all roles (wildcard)

    ## Common Roles

    - Admin: Full administrative access
    - User Management Admin: Can manage users and roles
    - Sensor Update Administrator: Can manage sensor updates
    - Falcon Admin: Falcon platform administration
    - Custom Roles: User-defined roles in your organization

    Use `falcon_get_available_role_ids` to list all available roles in your customer account.
""").strip()


class UserManagementModule(BaseModule):
    """Module for accessing and managing CrowdStrike Falcon users."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.query_users,
            name="query_users",
        )

        self._add_tool(
            server=server,
            method=self.retrieve_users,
            name="retrieve_users",
        )

        self._add_tool(
            server=server,
            method=self.retrieve_user_by_email,
            name="retrieve_user_by_email",
        )

        self._add_tool(
            server=server,
            method=self.get_user_roles,
            name="get_user_roles",
        )

        self._add_tool(
            server=server,
            method=self.get_available_role_ids,
            name="get_available_role_ids",
        )

        self._add_tool(
            server=server,
            method=self.get_roles,
            name="get_roles",
        )

        self._add_tool(
            server=server,
            method=self.grant_user_role_ids,
            name="grant_user_role_ids",
        )

        self._add_tool(
            server=server,
            method=self.revoke_user_role_ids,
            name="revoke_user_role_ids",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        user_search_fql_resource = TextResource(
            uri=AnyUrl("falcon://user-management/query/fql-guide"),
            name="falcon_query_users_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_query_users` tool.",
            text=USER_SEARCH_FQL_DOCUMENTATION,
        )

        role_fql_resource = TextResource(
            uri=AnyUrl("falcon://user-management/roles/fql-guide"),
            name="falcon_get_roles_fql_guide",
            description="Contains the guide for role queries and management.",
            text=ROLE_FQL_DOCUMENTATION,
        )

        self._add_resource(server, user_search_fql_resource)
        self._add_resource(server, role_fql_resource)

    def query_users(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL Syntax formatted string used to filter users. IMPORTANT: use the `falcon://user-management/query/fql-guide` resource when building this filter parameter. Examples: uid:'admin@example.com', status:'active', first_name:'John'",
            examples={"uid:'admin@example.com'", "status:'active'", "first_name:'John*'"},
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=500,
            description="The maximum records to return. [1-500]",
        ),
        offset: int | None = Field(
            default=None,
            description="The offset to start retrieving records from.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort users using these options:

                first_name: User's first name
                last_name: User's last name
                name: User's full name
                uid: User ID/email
                has_temporary_roles: Whether user has temporary roles

                Sort either asc (ascending) or desc (descending).
                Both formats are supported: 'first_name.desc' or 'first_name|desc'

                Examples: 'first_name.asc', 'uid.desc', 'name.asc'
            """).strip(),
            examples={"first_name.asc", "uid.desc"},
        ),
    ) -> List[str] | Dict[str, Any]:
        """Query and list users in your CrowdStrike environment.

        Returns user UUIDs that match the specified filter criteria.
        Use `falcon_retrieve_users` to get detailed information for returned UUIDs.

        IMPORTANT: You must use the `falcon://user-management/query/fql-guide` resource
        when you need to use the `filter` parameter. This resource contains the guide on
        how to build the FQL `filter` parameter for the `falcon_query_users` tool.
        """
        logger.debug("Querying users with filter: %s", filter)

        user_ids = self._base_search_api_call(
            operation="queryUserV1",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to query users",
        )

        return user_ids

    def retrieve_users(
        self,
        ids: List[str] = Field(
            description="User UUIDs to retrieve details for. You can get user UUIDs from the query_users operation. Maximum: 500 IDs per request."
        ),
    ) -> List[Dict[str, Any]] | Dict[str, Any]:
        """Retrieve detailed information for specified user UUIDs.

        This tool returns comprehensive user details including name, UID, and CID
        for one or more user UUIDs.
        """
        logger.debug("Retrieving user details for IDs: %s", ids)

        if not ids:
            return []

        return self._base_query_api_call(
            operation="retrieveUsersGETV1",
            query_params={"ids": ids},
            error_message="Failed to retrieve user details",
            default_result=[],
        )

    def retrieve_user_by_email(
        self,
        email: str = Field(
            description="User email address or username to search for"
        ),
    ) -> List[Dict[str, Any]] | Dict[str, Any]:
        """Retrieve a user by email address or username.

        This is a convenience tool that searches for a user by their email/username
        and returns their full details if found.
        """
        logger.debug("Searching for user by email: %s", email)

        # First, query for the user using FQL
        user_ids = self._base_search_api_call(
            operation="queryUserV1",
            search_params={
                "filter": f"uid:'{email}'",
                "limit": 1,
            },
            error_message=f"Failed to search for user by email: {email}",
        )

        if self._is_error(user_ids):
            return [user_ids]

        if not user_ids:
            return [{"error": f"User not found: {email}"}]

        # Get detailed information for the found user
        return self.retrieve_users(ids=user_ids)

    def get_user_roles(
        self,
        user_uuid: str = Field(
            description="User UUID to retrieve roles for"
        ),
        cid: str | None = Field(
            default=None,
            description="Customer ID to filter roles for. If not provided, returns roles for current CID."
        ),
        direct_only: bool = Field(
            default=False,
            description="If True, only return direct role assignments (not flight control grants)"
        ),
    ) -> Dict[str, Any]:
        """Retrieve roles assigned to a specific user.

        Returns both direct role assignments and flight control grants
        for the specified user against a CID.
        """
        logger.debug("Getting roles for user: %s", user_uuid)

        return self._base_search_api_call(
            operation="CombinedUserRolesV2",
            search_params={
                "user_uuid": user_uuid,
                "cid": cid,
                "direct_only": direct_only,
            },
            error_message=f"Failed to get roles for user: {user_uuid}",
        )

    def get_available_role_ids(
        self,
    ) -> Dict[str, Any]:
        """List all available role IDs in your customer account.

        Use the returned role IDs with `falcon_get_roles` to get detailed
        information about each role.
        """
        logger.debug("Getting available role IDs")

        return self._base_query_api_call(
            operation="GetAvailableRoleIds",
            error_message="Failed to get available role IDs",
        )

    def get_roles(
        self,
        ids: List[str] = Field(
            description="Role IDs to retrieve information for. Get role IDs from get_available_role_ids or get_user_roles operations."
        ),
    ) -> List[Dict[str, Any]] | Dict[str, Any]:
        """Retrieve detailed information for specified role IDs.

        Returns role details including permissions and descriptions for the
        specified role IDs.
        """
        logger.debug("Getting role details for IDs: %s", ids)

        if not ids:
            return []

        return self._base_query_api_call(
            operation="GetRoles",
            query_params={"ids": ids},
            error_message="Failed to get role details",
        )

    def grant_user_role_ids(
        self,
        user_uuid: str = Field(
            description="User UUID to grant roles to"
        ),
        role_ids: List[str] = Field(
            description="Role IDs to grant to the user"
        ),
    ) -> Dict[str, Any]:
        """Assign one or more roles to a user.

        Grants the specified roles to a user. After creating a user, use this
        operation to assign roles.
        """
        logger.debug("Granting roles %s to user %s", role_ids, user_uuid)

        return self._base_query_api_call(
            operation="GrantUserRoleIds",
            query_params={"user_uuid": user_uuid},
            body_params={"roleIds": role_ids},
            error_message=f"Failed to grant roles to user: {user_uuid}",
        )

    def revoke_user_role_ids(
        self,
        user_uuid: str = Field(
            description="User UUID to revoke roles from"
        ),
        role_ids: List[str] = Field(
            description="Role IDs to revoke from the user"
        ),
    ) -> Dict[str, Any]:
        """Revoke one or more roles from a user.

        Removes the specified roles from a user's assignments.
        """
        logger.debug("Revoking roles %s from user %s", role_ids, user_uuid)

        return self._base_query_api_call(
            operation="RevokeUserRoleIds",
            query_params={"user_uuid": user_uuid},
            body_params={"roleIds": role_ids},
            error_message=f"Failed to revoke roles from user: {user_uuid}",
        )
