"""
Identity Protection User Lookup module for Falcon MCP Server

This module provides tools for looking up users in your identity system
using the Identity Protection GraphQL API. Perfect for getting user context
when investigating alerts and detections.
"""

from textwrap import dedent
from typing import Any, Dict, List

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

# GraphQL query guide
IDENTITY_LOOKUP_GUIDE = dedent("""
    # Identity Protection User Lookup Guide

    Use this module to lookup users in your organization's identity system during alert investigation.

    ## What This Returns

    - **primaryDisplayName**: User's display name
    - **emails**: Email addresses
    - **accounts**: Active Directory account information (domain, SAM name)
    - **riskAssessment**: Security risk severity and description
    - **entityId**: Unique identifier in Identity Protection
    - **archived/learned**: User status flags

    ## Common Use Cases

    ### Lookup by Email
    ```
    lookup_user_identity with search_term="derek.dybdahl@respec.com"
    ```

    ### Lookup by Name
    ```
    lookup_user_identity with search_term="Derek Dybdahl"
    ```

    ### Lookup by Username
    ```
    lookup_user_identity with search_term="Derek.Dybdahl"
    ```

    ## Example Response

    When you lookup a user, you'll get:
    - Primary display name
    - All email addresses
    - Active Directory domain and account name
    - Risk assessment (severity, description, last updated)
    - Whether the identity is archived or learned

    ## Integration with Alerts

    When investigating a detection or incident:
    1. Extract the username/email from the alert
    2. Use `falcon_lookup_user_identity` to get full user details
    3. Check risk assessment for any flagged issues
    4. Use Active Directory info to understand the account context

    ## Performance

    Returns up to 10 matching users. Search is case-insensitive and fuzzy-matches
    across display names, emails, and account names.
""").strip()


class IdentityProtectionLookupModule(BaseModule):
    """Module for looking up users in Identity Protection for alert investigation."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.lookup_user_identity,
            name="lookup_user_identity",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        lookup_guide = TextResource(
            uri=AnyUrl("falcon://identity-protection/user-lookup-guide"),
            name="falcon_lookup_user_identity_guide",
            description="Guide for using the identity protection user lookup tool for alert investigation.",
            text=IDENTITY_LOOKUP_GUIDE,
        )

        self._add_resource(server, lookup_guide)

    def lookup_user_identity(
        self,
        search_term: str = Field(
            description="Email address, username, or display name to search for. Examples: 'derek.dybdahl@respec.com', 'Derek Dybdahl', 'Derek.Dybdahl'"
        ),
    ) -> List[Dict[str, Any]]:
        """Lookup a user in your identity system using Identity Protection GraphQL.

        This is perfect for getting user context when investigating alerts and detections.
        Search is case-insensitive and matches across emails, display names, and usernames.

        Returns user details including:
        - Display names (primary and secondary)
        - Email addresses
        - Active Directory account information
        - Risk assessment (severity, description, last updated)
        - Entity ID and status (archived, learned)

        Args:
            search_term: Email, username, or display name to search for

        Returns:
            List of matching user objects with full details
        """
        logger.debug("Looking up user identity: %s", search_term)

        # GraphQL query to search for users by email, name, or username
        graphql_query = f"""
        query SearchUsers($search: String!) {{
            entities(
                types: [USER]
                filter: {{
                    or: [
                        {{field: "primaryDisplayName", match: $search}}
                        {{field: "secondaryDisplayName", match: $search}}
                        {{field: "emails", match: $search}}
                        {{field: "accountNames", match: $search}}
                    ]
                }}
                first: 10
            ) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    secondaryDisplayName
                    emails
                    accounts {{
                        ... on ActiveDirectoryAccountDescriptor {{
                            domain
                            name
                            samAccountName
                        }}
                    }}
                    riskAssessment {{
                        severity
                        description
                        lastUpdatedAt
                    }}
                    archived
                    learned
                }}
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
            }}
        }}
        """

        variables = {"search": search_term}

        # Call the Identity Protection GraphQL API
        response = self._base_query_api_call(
            operation="api_preempt_proxy_post_graphql",
            body_params={
                "query": graphql_query,
                "variables": variables,
            },
            error_message=f"Failed to lookup user: {search_term}",
            default_result=[],
        )

        # Handle error responses
        if self._is_error(response):
            logger.error("Error looking up user: %s", response)
            return [{"error": response.get("error"), "search_term": search_term}]

        # Extract entities from GraphQL response
        # The response structure is: {"data": {"entities": {"nodes": [...]}}}
        try:
            if isinstance(response, dict):
                data = response.get("data", {})
                entities = data.get("entities", {})
                nodes = entities.get("nodes", [])

                if nodes:
                    logger.debug(
                        "Found %d user(s) matching: %s", len(nodes), search_term
                    )
                    return nodes
                else:
                    logger.debug("No users found matching: %s", search_term)
                    return [
                        {
                            "not_found": True,
                            "search_term": search_term,
                            "message": f"No users found matching '{search_term}'",
                        }
                    ]
            else:
                logger.error("Unexpected response format: %s", response)
                return [{"error": "Unexpected response format"}]

        except Exception as e:
            logger.error("Error parsing GraphQL response: %s", e)
            return [{"error": str(e)}]
