from typing import Optional

from datetime import datetime, timedelta

import logging

from pymisp import MISPEvent

from app.misp.client import MISPClient

logger = logging.getLogger(__name__)


async def create_event(
    misp_client: MISPClient, info: str, distribution: int = 1, threat_level_id: int = 3, analysis: int = 0, date: Optional[str] = None
) -> str:
    """
    Create a new MISP event with basic information.
    """

    try:
        event = MISPEvent()
        event.info = info
        event.distribution = distribution
        event.threat_level_id = threat_level_id
        event.analysis = analysis

        if date:
            event.date = date

        result = misp_client.client.add_event(event)

        if "Event" in result:
            event_data = result["Event"]
            return f"""✅ **Event Created Successfully!**

**Event Details:**
- Event ID: {event_data.get("id")}
- UUID: {event_data.get("uuid")}
- Info: {event_data.get("info")}
- Distribution: {event_data.get("distribution")} ({_get_distribution_name(event_data.get("distribution"))})
- Threat Level: {event_data.get("threat_level_id")} ({_get_threat_level_name(event_data.get("threat_level_id"))})
- Analysis: {event_data.get("analysis")} ({_get_analysis_name(event_data.get("analysis"))})
- Date: {event_data.get("date")}
- Created: {event_data.get("timestamp")}

**Next Steps:**
You can now add attributes to this event using the `add_attribute` tool with event ID: {event_data.get("id")}"""
        else:
            return f"❌ Failed to create event. Response: {result}"

    except Exception as e:
        logger.error(f"Failed to create event: {e}")
        return f"""❌ **Failed to create event.**

**Error:** {str(e)}

Please check your input parameters and MISP connection."""


async def get_event(misp_client: MISPClient, event_id: str, include_attributes: bool = True) -> str:
    """
    Retrieve a MISP event by ID or UUID.
    """

    try:
        result = misp_client.client.get_event(event_id, pythonify=True)

        if isinstance(result, MISPEvent):
            output = f"""📋 **Event Details:**

**Basic Information:**
- Event ID: {result.id}
- UUID: {result.uuid}
- Info: {result.info}
- Distribution: {result.distribution} ({_get_distribution_name(result.distribution)})
- Threat Level: {result.threat_level_id} ({_get_threat_level_name(result.threat_level_id)})
- Analysis: {result.analysis} ({_get_analysis_name(result.analysis)})
- Date: {result.date}
- Published: {"Yes" if result.published else "No"}
- Created: {result.timestamp}
- Modified: {result.timestamp}

**Organization:**
- Org ID: {result.org_id}
- Orgc ID: {result.orgc_id}"""

            if include_attributes and result.attributes:
                output += f"\n\n**Attributes ({len(result.attributes)}):**"
                for attr in result.attributes[:10]:  # Limit to first 10 attributes
                    output += f"\n- {attr.type}: {attr.value} (Category: {attr.category})"

                if len(result.attributes) > 10:
                    output += f"\n... and {len(result.attributes) - 10} more attributes"

            if result.tags:
                output += f"\n\n**Tags ({len(result.tags)}):**"
                for tag in result.tags:
                    output += f"\n- {tag.name}"

            return output
        else:
            return f"❌ Event not found or invalid response: {result}"

    except Exception as e:
        logger.error(f"Failed to get event {event_id}: {e}")
        return f"""❌ **Failed to retrieve event.**

**Event ID:** {event_id}
**Error:** {str(e)}

Please verify the event ID/UUID and your access permissions."""


async def search_events(
    misp_client: MISPClient,
    limit: int = 10,
    days_back: Optional[int] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    org: Optional[str] = None,
    tags: Optional[str] = None,
    threat_level: Optional[int] = None,
) -> str:
    """
    Search for MISP events with various filters.
    """
    try:
        # Limit results to max 50 for performance
        limit = min(limit, 50)

        search_params = {"limit": limit, "pythonify": True}

        # Handle date parameters
        if days_back:
            date_from = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")

        if date_from:
            search_params["date_from"] = date_from
        if date_to:
            search_params["date_to"] = date_to
        if org:
            search_params["org"] = org
        if tags:
            search_params["tags"] = tags
        if threat_level:
            search_params["threat_level"] = threat_level

        results = misp_client.client.search(controller="events", **search_params)

        if not results:
            return "📭 No events found matching your search criteria."

        output = f"🔍 **Found {len(results)} event(s):**\n"

        for event in results:
            if hasattr(event, "Event"):
                event_data = event.Event
            else:
                event_data = event

            output += f"""
**Event ID: {event_data.id}**
- Info: {event_data.info}
- Date: {event_data.date}
- Threat Level: {_get_threat_level_name(event_data.threat_level_id)}
- Analysis: {_get_analysis_name(event_data.analysis)}
- Published: {"Yes" if event_data.published else "No"}
- Attributes: {len(getattr(event_data, "attributes", []))}
"""

        if len(results) == limit:
            output += f"\n⚠️ Results limited to {limit} events. Use more specific filters to see different results."

        return output

    except Exception as e:
        logger.error(f"Failed to search events: {e}")
        return f"""❌ **Failed to search events.**

**Error:** {str(e)}

Please check your search parameters and MISP connection."""


def _get_distribution_name(dist_id: int) -> str:
    """Convert distribution ID to readable name."""
    distribution_map = {0: "Your Organization Only", 1: "This Community Only", 2: "Connected Communities", 3: "All Communities"}
    return distribution_map.get(dist_id, f"Unknown ({dist_id})")


def _get_threat_level_name(level_id: int) -> str:
    """Convert threat level ID to readable name."""
    threat_level_map = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
    return threat_level_map.get(level_id, f"Unknown ({level_id})")


def _get_analysis_name(analysis_id: int) -> str:
    """Convert analysis ID to readable name."""
    analysis_map = {0: "Initial", 1: "Ongoing", 2: "Complete"}
    return analysis_map.get(analysis_id, f"Unknown ({analysis_id})")
