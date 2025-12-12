"""
Automated Investigation module for Falcon MCP Server

This module provides comprehensive detection investigation by automatically
gathering all contextual information: user context, related detections,
host details, and behavioral patterns.
"""

from textwrap import dedent
from typing import Any, Dict, List, Optional

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.logging import get_logger
from falcon_mcp.modules.base import BaseModule

logger = get_logger(__name__)

# Investigation guide
INVESTIGATION_GUIDE = dedent("""
    # Automated Detection Investigation Guide

    The investigation tool automatically gathers comprehensive context for a detection
    to help determine if it's a true or false positive.

    ## What Gets Investigated

    For a given detection, the tool automatically:

    1. **Detection Details**: Full detection information
    2. **User Context**: If a user is involved:
       - All systems where they've logged in
       - Login history and timestamps
       - Network information (IPs, MAC address)
       - OS and agent versions
    3. **Related Detections**: Other detections on the user's systems
    4. **Host Details**: Full system information where detection occurred
    5. **Behavioral Pattern**: Detection severity, tactic, technique

    ## Usage

    ### Basic Investigation
    ```
    investigate_detection with detection_id="<detection_id>"
    ```

    ### Automated via Codex
    When you provide a detection, Codex will automatically:
    1. Extract the detection details
    2. Identify the associated user (if any)
    3. Look up all user's systems
    4. Find related detections
    5. Gather host context
    6. Present comprehensive investigation summary

    ## Investigation Output

    You'll receive:

    **Detection Summary**
    - Detection ID and timestamp
    - Severity and confidence
    - Tactic and technique (MITRE ATT&CK)
    - Behavior type and description

    **User Context** (if applicable)
    - Username and domain
    - All systems they've accessed
    - Last login times
    - Network details (IPs, MAC addresses)
    - OS versions and Falcon agent status

    **Related Detections**
    - Other detections on user's systems
    - Timeline of related activity
    - Severity progression

    **Host Details**
    - System information
    - Policy status
    - Sensor health
    - Last activity

    ## True/False Positive Determination

    With all this context, you can quickly determine:

    **True Positive Signs**:
    - Unexpected user on system
    - Off-hours activity
    - Cluster of detections from one user
    - High-severity behaviors
    - Suspicious IP addresses

    **False Positive Signs**:
    - Expected legitimate user
    - Business hours activity
    - Known benign behavior
    - Low confidence detection
    - Isolated single event
""").strip()


class InvestigationModule(BaseModule):
    """Module for automated comprehensive detection investigation."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.investigate_detection,
            name="investigate_detection",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        investigation_guide = TextResource(
            uri=AnyUrl("falcon://investigation/guide"),
            name="falcon_investigate_detection_guide",
            description="Guide for using automated detection investigation to gather comprehensive context.",
            text=INVESTIGATION_GUIDE,
        )

        self._add_resource(server, investigation_guide)

    def investigate_detection(
        self,
        detection_id: str = Field(
            description="Detection ID to investigate. Example: 'ldt:device_id:timestamp:uuid'"
        ),
        include_related: bool = Field(
            default=True,
            description="Whether to search for related detections on user's systems",
        ),
    ) -> Dict[str, Any]:
        """Comprehensively investigate a detection by gathering all contextual information.

        Automatically:
        1. Gets detection details (severity, behavior, tactic)
        2. Identifies the associated user/device
        3. Looks up user context (all systems they use)
        4. Finds related detections on those systems
        5. Gathers host details and sensor status

        Returns a complete investigation package with all information needed
        to determine if the detection is a true or false positive.

        Args:
            detection_id: The detection ID to investigate
            include_related: Whether to search for related detections (default: True)

        Returns:
            Comprehensive investigation object with detection, user, related detections,
            and host details
        """
        logger.debug("Investigating detection: %s", detection_id)

        investigation = {
            "detection_id": detection_id,
            "investigation_status": "in_progress",
            "detection_details": None,
            "user_context": None,
            "related_detections": [],
            "host_details": None,
            "investigation_summary": {},
        }

        # Step 1: Get detection details
        logger.debug("Step 1: Fetching detection details")
        detection_details = self._get_detection_details(detection_id)
        if self._is_error(detection_details):
            investigation["investigation_status"] = "failed"
            investigation["error"] = detection_details.get("error")
            return investigation

        investigation["detection_details"] = detection_details

        # Extract device_id and username from detection
        device_id = detection_details.get("device_id")
        username = detection_details.get("username")
        hostname = detection_details.get("hostname")

        logger.debug(
            "Detection involves device_id=%s, username=%s, hostname=%s",
            device_id,
            username,
            hostname,
        )

        # Step 2: Get host details
        if device_id:
            logger.debug("Step 2: Fetching host details for device_id=%s", device_id)
            host_details = self._get_host_details(device_id)
            if not self._is_error(host_details):
                investigation["host_details"] = host_details

        # Step 3: Look up user context
        if username:
            logger.debug("Step 3: Looking up user context for username=%s", username)
            user_context = self._lookup_user_context(username)
            if not self._is_error(user_context):
                investigation["user_context"] = user_context

        # Step 4: Find related detections
        if include_related and device_id:
            logger.debug(
                "Step 4: Searching for related detections on device_id=%s", device_id
            )
            related = self._get_related_detections(device_id, username)
            if related and not self._is_error(related):
                investigation["related_detections"] = related

        # Build investigation summary
        investigation["investigation_status"] = "complete"
        investigation["investigation_summary"] = self._build_summary(
            investigation
        )

        logger.debug("Investigation complete for detection: %s", detection_id)
        return investigation

    def _get_detection_details(self, detection_id: str) -> Dict[str, Any]:
        """Get details for a specific detection."""
        logger.debug("Getting detection details for: %s", detection_id)

        response = self._base_get_by_ids(
            operation="GetDetectionsDetail",
            ids=[detection_id],
            id_key="ids",
            error_message=f"Failed to get detection details for {detection_id}",
        )

        if self._is_error(response):
            return response

        # Response is a list, get first element
        if isinstance(response, list) and response:
            return response[0]
        elif isinstance(response, dict):
            return response
        else:
            return {"error": f"Unexpected response format for detection {detection_id}"}

    def _get_host_details(self, device_id: str) -> Dict[str, Any]:
        """Get details for a specific host/device."""
        logger.debug("Getting host details for device_id: %s", device_id)

        response = self._base_get_by_ids(
            operation="GetDeviceDetails",
            ids=[device_id],
            id_key="ids",
            error_message=f"Failed to get host details for {device_id}",
        )

        if self._is_error(response):
            return response

        # Response is a list, get first element
        if isinstance(response, list) and response:
            return response[0]
        elif isinstance(response, dict):
            return response
        else:
            return {"error": f"Unexpected response format for device {device_id}"}

    def _lookup_user_context(self, username: str) -> Dict[str, Any]:
        """Look up user context by username (all systems they've accessed)."""
        logger.debug("Looking up user context for username: %s", username)

        # Search for hosts where this user last logged in
        fql_filter = f"last_login_user:'{username}'"

        response = self._base_search_api_call(
            operation="QueryDevicesByFilter",
            search_params={
                "filter": fql_filter,
                "limit": 100,
                "sort": "last_seen.desc",
            },
            error_message=f"Failed to lookup user context for {username}",
            default_result=[],
        )

        if self._is_error(response):
            return response

        # Get device IDs
        device_ids = response if isinstance(response, list) else ([response] if response else [])

        if not device_ids:
            return {"username": username, "systems": []}

        # Get full details for those devices
        device_details = self._base_get_by_ids(
            operation="GetDeviceDetails",
            ids=device_ids,
            id_key="ids",
            error_message=f"Failed to get details for {username} systems",
        )

        if self._is_error(device_details):
            return device_details

        devices = device_details if isinstance(device_details, list) else [device_details]

        # Extract relevant user context
        systems = []
        for device in devices:
            if isinstance(device, dict):
                systems.append(
                    {
                        "hostname": device.get("hostname"),
                        "device_id": device.get("device_id"),
                        "last_login_user": device.get("last_login_user"),
                        "last_login_timestamp": device.get("last_login_timestamp"),
                        "last_seen": device.get("last_seen"),
                        "external_ip": device.get("external_ip"),
                        "local_ip": device.get("local_ip"),
                        "os_version": device.get("os_version"),
                        "machine_domain": device.get("machine_domain"),
                        "agent_version": device.get("agent_version"),
                    }
                )

        return {
            "username": username,
            "systems_count": len(systems),
            "systems": systems,
        }

    def _get_related_detections(
        self, device_id: str, username: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find other detections on the user's systems."""
        logger.debug(
            "Getting related detections for device_id=%s, username=%s",
            device_id,
            username,
        )

        # Build FQL filter for detections on this device
        fql_filter = f"device_id:'{device_id}'"

        response = self._base_search_api_call(
            operation="QueryDetects",
            search_params={
                "filter": fql_filter,
                "limit": 50,
                "sort": "first_behavior.desc",
            },
            error_message=f"Failed to find related detections for {device_id}",
            default_result=[],
        )

        if self._is_error(response):
            return []

        # Response is list of detection IDs
        detection_ids = response if isinstance(response, list) else ([response] if response else [])

        if not detection_ids:
            return []

        # Limit to avoid excessive API calls
        detection_ids = detection_ids[:10]

        # Get full details for related detections
        detection_details = self._base_get_by_ids(
            operation="GetDetectionsDetail",
            ids=detection_ids,
            id_key="ids",
            error_message=f"Failed to get details for related detections",
        )

        if self._is_error(detection_details):
            return []

        detections = (
            detection_details if isinstance(detection_details, list) else [detection_details]
        )

        # Extract summary for each
        related = []
        for detection in detections:
            if isinstance(detection, dict):
                related.append(
                    {
                        "detection_id": detection.get("detection_id"),
                        "timestamp": detection.get("timestamp"),
                        "severity": detection.get("severity"),
                        "behavior": detection.get("behavior"),
                        "tactic": detection.get("tactic"),
                        "technique": detection.get("technique"),
                    }
                )

        return related

    def _build_summary(self, investigation: Dict[str, Any]) -> Dict[str, Any]:
        """Build investigation summary for quick assessment."""
        summary = {
            "key_findings": [],
            "risk_indicators": [],
            "investigation_tips": [],
        }

        detection = investigation.get("detection_details", {})
        user = investigation.get("user_context", {})
        host = investigation.get("host_details", {})
        related = investigation.get("related_detections", [])

        # Key findings
        if detection.get("severity"):
            summary["key_findings"].append(
                f"Detection severity: {detection.get('severity')}"
            )
        if user.get("systems_count"):
            summary["key_findings"].append(
                f"User has {user.get('systems_count')} known systems"
            )
        if related:
            summary["key_findings"].append(
                f"Found {len(related)} related detections on user's systems"
            )

        # Risk indicators
        if detection.get("severity") == "high":
            summary["risk_indicators"].append("High severity detection")
        if len(related) > 3:
            summary["risk_indicators"].append("Multiple related detections (cluster)")
        if user.get("systems"):
            # Check for unusual systems
            systems = user.get("systems", [])
            if len(systems) > 5:
                summary["risk_indicators"].append(
                    "User accessing many systems (unusual activity pattern)"
                )

        # Investigation tips
        if detection.get("timestamp"):
            summary["investigation_tips"].append(
                f"Check if activity at {detection.get('timestamp')} is expected"
            )
        if user.get("systems"):
            summary["investigation_tips"].append(
                "Verify user's legitimate systems list matches found systems"
            )
        if related:
            summary["investigation_tips"].append(
                "Examine timeline of related detections for pattern"
            )

        return summary
