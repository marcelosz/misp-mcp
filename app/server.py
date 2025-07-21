#!/usr/bin/env python3
"""
MISP MCP Server - MVP Implementation

A Model Context Protocol server that provides basic MISP (Malware Information Sharing Platform)
integration capabilities for Large Language Models.

This MVP includes:
- Connection testing and version checking
- Basic event management (create, get, search)
- Basic attribute management (add, get)
- Recent events resources

Usage:
    python -m app.server
"""

import asyncio
import logging

from fastmcp import FastMCP

from app.config import get_settings
from app.misp.client import MISPClient

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Create main MCP server instance
mcp = FastMCP(
    name="MISP MCP Server",
    instructions="""
    This is a MCP server for Malware Information Sharing Platform (MISP).

    You can use the following tools:
    - check_connection: Test the connection to the MISP instance and verify authentication.
    - get_version: Get detailed version information from the MISP instance.
    - create_event: Create a new MISP event with basic information.
    - get_event: Retrieve a MISP event by ID or UUID.
    - search_events: Search for MISP events with various filters.
    - add_attribute: Add an attribute to a MISP event.

    The following resources are available:
    - events/recent/{days}: Get recent MISP events from the last N days.
    """,
)

# Global MISP client instance
misp_client = None


async def initialize_misp_client():
    """Initialize the MISP client with configuration."""
    global misp_client
    try:
        settings = get_settings()
        misp_client = MISPClient(settings)
        logger.info(f"MISP client initialized for {settings.misp_url}")
        return misp_client
    except Exception as e:
        logger.error(f"Failed to initialize MISP client: {e}")
        raise


# Connection tools
@mcp.tool()
async def check_connection() -> str:
    """
    Test the connection to the MISP instance and verify authentication.

    Returns:
        Connection status with version information or error message.
    """
    from app.tools.connection import check_connection as _check_connection

    return await _check_connection(misp_client)


@mcp.tool()
async def get_version() -> str:
    """
    Get detailed version information from the MISP instance.

    Returns:
        Detailed version information including API and application versions.
    """
    from app.tools.connection import get_version as _get_version

    return await _get_version(misp_client)


# Event management tools
@mcp.tool()
async def create_event(info: str, distribution: int = 1, threat_level_id: int = 3, analysis: int = 0, date: str = None) -> str:
    """
    Create a new MISP event with basic information.

    Args:
        info: Event description/information (required)
        distribution: Distribution level (0=Your Org, 1=This Community, 2=Connected Communities, 3=All Communities)
        threat_level_id: Threat level (1=High, 2=Medium, 3=Low, 4=Undefined)
        analysis: Analysis status (0=Initial, 1=Ongoing, 2=Complete)
        date: Event date in YYYY-MM-DD format (defaults to today)

    Returns:
        Success message with event ID or error information.
    """
    from app.tools.events import create_event as _create_event

    return await _create_event(misp_client, info, distribution, threat_level_id, analysis, date)


@mcp.tool()
async def get_event(event_id: str, include_attributes: bool = True) -> str:
    """
    Retrieve a MISP event by ID or UUID.

    Args:
        event_id: Event ID or UUID
        include_attributes: Whether to include event attributes in the response

    Returns:
        Event details including attributes if requested.
    """
    from app.tools.events import get_event as _get_event

    return await _get_event(misp_client, event_id, include_attributes)


@mcp.tool()
async def search_events(
    limit: int = 10, days_back: int = None, date_from: str = None, date_to: str = None, org: str = None, tags: str = None, threat_level: int = None
) -> str:
    """
    Search for MISP events with various filters.

    Args:
        limit: Maximum number of events to return (default: 10, max: 50)
        days_back: Number of days to look back from today
        date_from: Start date in YYYY-MM-DD format
        date_to: End date in YYYY-MM-DD format
        org: Organization name to filter by
        tags: Tag name to filter by
        threat_level: Threat level ID to filter by (1=High, 2=Medium, 3=Low, 4=Undefined)

    Returns:
        List of matching events with basic information.
    """
    from app.tools.events import search_events as _search_events

    return await _search_events(misp_client, limit, days_back, date_from, date_to, org, tags, threat_level)


# Attribute management tools
@mcp.tool()
async def add_attribute(
    event_id: str, attribute_type: str, value: str, category: str, comment: str = None, to_ids: bool = False, distribution: int = 5
) -> str:
    """
    Add an attribute to a MISP event.

    Args:
        event_id: ID or UUID of the event to add the attribute to
        attribute_type: Type of attribute (e.g., 'ip-src', 'domain', 'md5', 'url', 'filename')
        value: The actual value of the attribute
        category: Category of the attribute (e.g., 'Network activity', 'Payload delivery', 'Artifacts dropped')
        comment: Optional comment describing the attribute
        to_ids: Whether this attribute should be used for IDS detection
        distribution: Distribution level (0-3 for specific levels, 5=Inherit from event)

    Returns:
        Success message with attribute details or error information.
    """
    from app.tools.attributes import add_attribute as _add_attribute

    return await _add_attribute(misp_client, event_id, attribute_type, value, category, comment, to_ids, distribution)


@mcp.tool()
async def get_event_attributes(event_id: str, limit: int = 20, attribute_type: str = None, category: str = None) -> str:
    """
    Get all attributes for a specific MISP event.

    Args:
        event_id: ID or UUID of the event to get attributes for
        limit: Maximum number of attributes to return (default: 20, max: 100)
        attribute_type: Filter by specific attribute type (optional)
        category: Filter by specific category (optional)

    Returns:
        List of attributes with their details.
    """
    from app.tools.attributes import get_event_attributes as _get_event_attributes

    return await _get_event_attributes(misp_client, event_id, limit, attribute_type, category)


# Resources
@mcp.resource("events/recent/{days}")
async def get_recent_events(days: str) -> str:
    """Get recent MISP events from the last N days."""
    from app.resources.events import get_recent_events as _get_recent_events

    return await _get_recent_events(misp_client, days)


async def main():
    """Main entry point for the MCP server."""
    try:
        # Initialize MISP client
        await initialize_misp_client()

        # Test connection on startup
        result = misp_client.test_connection()
        if result["status"] == "connected":
            logger.info(f"✅ Successfully connected to MISP: {result.get('version')}")
        else:
            logger.warning(f"⚠️ MISP connection test failed: {result.get('message')}")

        # Run the server
        logger.info("🚀 Starting MISP MCP Server with FastMCP...")
        await mcp.run_async(transport="sse")

    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == "__main__":
    """Entry point when running directly."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MISP MCP Server stopped")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        exit(1)
