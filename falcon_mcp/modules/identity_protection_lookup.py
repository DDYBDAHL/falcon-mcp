"""
User Context Lookup module for Falcon MCP Server

This module provides tools for looking up user context during alert investigation.
Since Identity Protection GraphQL may not be available, this uses a pragmatic approach:
lookup users by searching for hosts where they last logged in.
"""

from textwrap import dedent
from typing import Any, Dict, List

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

# User lookup guide
USER_LOOKUP_GUIDE = dedent("""
    # User Context Lookup Guide

    This tool looks up user context by searching for hosts where they logged in.
    This is practical for alert investigation - when you see a username in an alert,
    find what systems they use to get their context.

    ## What This Returns

    For each host the user logged into:
    - **last_login_user**: The username
    - **last_login_timestamp**: When they last logged in
    - **hostname**: System they logged into
    - **os_version**: Windows/Linux/etc
    - **external_ip**: Their external IP when they logged in
    - **local_ip**: Internal network IP
    - **machine_domain**: Domain the system is joined to
    - **agent_version**: Falcon agent version on that system
    - **policies**: Active Falcon policies

    ## Common Use Cases

    ### Lookup by Exact Username
    ```
    lookup_user_context with search_term="Derek.Dybdahl"
    ```

    ### Lookup by Partial Name
    ```
    lookup_user_context with search_term="Derek*"
    ```

    ### Lookup by Domain Username
    ```
    lookup_user_context with search_term="RESPEC\\Derek.Dybdahl"
    ```

    ## Example Response

    When you lookup a user, you'll get a list of hosts they've logged into with:
    - Exact username format (domain\\user or UPN)
    - Last login timestamp
    - System details (OS, hostname, IPs)
    - Domain information
    - When the system was last seen

    ## Integration with Alert Investigation

    When investigating a detection with a username:
    1. Extract the username from the alert (e.g., "Derek.Dybdahl")
    2. Use `falcon_lookup_user_context` to find their systems
    3. Check last login time, IP addresses, and OS versions
    4. Search for detections on those specific hosts if needed

    ## Search Tips

    - Use wildcards: "Derek*" matches Derek.Dybdahl, Derek_Test, etc.
    - Try partial matches: "derek" is case-insensitive
    - If no results, try variations: Derek vs derek.dybdahl vs DOMAIN\\Derek
    - The search returns systems where user LAST logged in (not currently logged in)
""").strip()


class IdentityProtectionLookupModule(BaseModule):
    """Module for looking up user context via host data for alert investigation."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.lookup_user_context,
            name="lookup_user_context",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        lookup_guide = TextResource(
            uri=AnyUrl("falcon://identity-protection/user-lookup-guide"),
            name="falcon_lookup_user_context_guide",
            description="Guide for looking up user context via host login history during alert investigation.",
            text=USER_LOOKUP_GUIDE,
        )

        self._add_resource(server, lookup_guide)

    def lookup_user_context(
        self,
        search_term: str = Field(
            description="Username to search for in host login history. Examples: 'Derek.Dybdahl', 'Derek*', 'RESPEC\\\\Derek.Dybdahl', 'derek' (case-insensitive). Wildcards supported."
        ),
    ) -> List[Dict[str, Any]]:
        """Lookup user context by finding hosts where they logged in.

        This tool searches for hosts where a user last logged in, returning
        system details, IP addresses, domain info, and login timestamps.
        Perfect for getting user context during alert investigation.

        Uses FQL filter on last_login_user field. Supports wildcards and
        case-insensitive matching.

        Returns:
            List of host records where user logged in with full details
        """
        logger.debug("Looking up user context: %s", search_term)

        # Build FQL filter for searching by last login user
        # Supports wildcards and case-insensitive matching
        fql_filter = f"last_login_user:'{search_term}'"

        logger.debug("Using FQL filter: %s", fql_filter)

        # Search hosts using FQL filter
        response = self._base_search_api_call(
            operation="QueryDevicesByFilter",
            search_params={
                "filter": fql_filter,
                "limit": 100,
                "sort": "last_seen.desc",
            },
            error_message=f"Failed to lookup user context: {search_term}",
            default_result=[],
        )

        # Handle error responses
        if self._is_error(response):
            logger.error("Error looking up user context: %s", response)
            return [{"error": response.get("error"), "search_term": search_term}]

        # response should be a list of device IDs from QueryDevicesByFilter
        if not response:
            logger.debug("No hosts found for user: %s", search_term)
            return [
                {
                    "not_found": True,
                    "search_term": search_term,
                    "message": f"No systems found with last_login_user matching '{search_term}'",
                }
            ]

        # Now get full details for those devices
        device_ids = response if isinstance(response, list) else [response]
        logger.debug("Found %d device(s), fetching details", len(device_ids))

        device_details = self._base_get_by_ids(
            operation="GetDeviceDetails",
            ids=device_ids,
            error_message=f"Failed to get details for user {search_term} hosts",
        )

        if self._is_error(device_details):
            logger.error("Error getting device details: %s", device_details)
            return [{"error": device_details.get("error")}]

        if not device_details:
            logger.debug("No device details returned")
            return [
                {
                    "not_found": True,
                    "search_term": search_term,
                    "message": "Found hosts but could not retrieve details",
                }
            ]

        # Extract and format user context from device details
        user_contexts = []

        devices = device_details if isinstance(device_details, list) else [device_details]
        for device in devices:
            if isinstance(device, dict):
                # Extract relevant user/context fields
                context = {
                    "last_login_user": device.get("last_login_user"),
                    "last_login_user_sid": device.get("last_login_user_sid"),
                    "last_login_timestamp": device.get("last_login_timestamp"),
                    "hostname": device.get("hostname"),
                    "machine_domain": device.get("machine_domain"),
                    "os_version": device.get("os_version"),
                    "platform_name": device.get("platform_name"),
                    "build_number": device.get("build_number"),
                    "external_ip": device.get("external_ip"),
                    "local_ip": device.get("local_ip"),
                    "mac_address": device.get("mac_address"),
                    "agent_version": device.get("agent_version"),
                    "last_seen": device.get("last_seen"),
                    "first_seen": device.get("first_seen"),
                    "device_id": device.get("device_id"),
                    "cid": device.get("cid"),
                }
                user_contexts.append(context)

        if user_contexts:
            logger.debug(
                "Found %d system(s) for user: %s", len(user_contexts), search_term
            )
            return user_contexts
        else:
            logger.debug("No user context extracted from device details")
            return [
                {
                    "not_found": True,
                    "search_term": search_term,
                    "message": "Could not extract user context from host details",
                }
            ]
