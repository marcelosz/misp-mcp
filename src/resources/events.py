import fastmcp
import logging
from datetime import datetime, timedelta
from ..misp.client import MISPClient

logger = logging.getLogger(__name__)
mcp = fastmcp.FastMCP("MISP Event Resources")


@mcp.resource("events/recent/{days}")
async def get_recent_events(misp_client: MISPClient, days: str) -> str:
    """
    Get recent MISP events from the last N days.

    Args:
        days: Number of days to look back (supported: 7, 30)

    Returns:
        JSON-formatted list of recent events with basic information.
    """
    try:
        # Validate days parameter
        if days not in ["7", "30"]:
            return f"❌ Invalid days parameter: {days}. Supported values: 7, 30"

        days_int = int(days)
        date_from = (datetime.now() - timedelta(days=days_int)).strftime("%Y-%m-%d")

        # Search for recent events
        search_params = {
            "date_from": date_from,
            "limit": 50,  # Reasonable limit for resources
            "pythonify": True,
        }

        results = misp_client.client.search(controller="events", **search_params)

        if not results:
            return f"""{{
    "timeframe": "Last {days} days",
    "date_from": "{date_from}",
    "count": 0,
    "events": [],
    "message": "No events found in the specified timeframe"
}}"""

        # Format events for resource consumption
        events_data = []
        for event in results:
            if hasattr(event, "Event"):
                event_data = event.Event
            else:
                event_data = event

            events_data.append(
                {
                    "id": str(event_data.id),
                    "uuid": str(event_data.uuid),
                    "info": str(event_data.info),
                    "date": str(event_data.date),
                    "threat_level": {"id": int(event_data.threat_level_id), "name": _get_threat_level_name(event_data.threat_level_id)},
                    "analysis": {"id": int(event_data.analysis), "name": _get_analysis_name(event_data.analysis)},
                    "distribution": {"id": int(event_data.distribution), "name": _get_distribution_name(event_data.distribution)},
                    "published": bool(event_data.published),
                    "attribute_count": len(getattr(event_data, "attributes", [])),
                    "timestamp": str(event_data.timestamp),
                    "org_id": str(event_data.org_id),
                    "orgc_id": str(event_data.orgc_id),
                }
            )

        # Sort by timestamp (most recent first)
        events_data.sort(key=lambda x: x["timestamp"], reverse=True)

        return f"""{{
    "timeframe": "Last {days} days",
    "date_from": "{date_from}",
    "date_to": "{datetime.now().strftime("%Y-%m-%d")}",
    "count": {len(events_data)},
    "events": {events_data},
    "summary": {{
        "total_events": {len(events_data)},
        "published_events": {sum(1 for e in events_data if e["published"])},
        "high_threat": {sum(1 for e in events_data if e["threat_level"]["id"] == 1)},
        "medium_threat": {sum(1 for e in events_data if e["threat_level"]["id"] == 2)},
        "low_threat": {sum(1 for e in events_data if e["threat_level"]["id"] == 3)},
        "completed_analysis": {sum(1 for e in events_data if e["analysis"]["id"] == 2)}
    }}
}}"""

    except Exception as e:
        logger.error(f"Failed to get recent events for {days} days: {e}")
        return f"""{{
    "error": "Failed to retrieve recent events",
    "message": "{str(e)}",
    "timeframe": "Last {days} days"
}}"""


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
