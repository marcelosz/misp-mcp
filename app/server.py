#!/usr/bin/env python3
"""
MISP MCP Server

A Model Context Protocol server that provides basic MISP (Malware Information Sharing Platform)
integration capabilities for Large Language Models.
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
    name="MISP",
    instructions="""
    This is a MCP server for Malware Information Sharing Platform (MISP).

    You can use the following tools:
    - check_connection: Test the connection to the MISP instance and verify authentication.
    - get_version: Get detailed version information from the MISP instance.
    - create_event: Create a new MISP event with basic information.
    - get_event: Retrieve a MISP event by ID or UUID.
    - search_events: Search for MISP events with various filters.
    - add_attribute: Add an attribute to a MISP event.

    You can also use the following resources:
    - events/recent/{days}: Get recent MISP events from the last N days (Supported values: 7, 30, 90. Default: 7)
    - feeds: Get information about MISP feeds.
    """,
)

# Global settings instance
settings = get_settings()

# Global MISP client instance
misp_client = None


def get_misp_client() -> MISPClient:
    global misp_client

    # Check if already initialized
    if misp_client is not None:
        return misp_client

    try:
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
    """
    from app.tools.connection import check_connection as _check_connection

    return _check_connection(get_misp_client())


@mcp.tool()
async def get_version() -> str:
    """
    Get detailed version information from the MISP instance.
    """
    from app.tools.connection import get_version as _get_version

    return _get_version(get_misp_client())


# Event management tools
@mcp.tool()
async def create_event(info: str, distribution: int = 1, threat_level_id: int = 3, analysis: int = 0, date: str = None) -> str:
    """
    Create a new MISP event with basic information.
    """
    from app.tools.events import create_event as _create_event

    return _create_event(get_misp_client(), info, distribution, threat_level_id, analysis, date)


@mcp.tool()
async def get_event(event_id: str, include_attributes: bool = True) -> str:
    """
    Retrieve a MISP event by ID or UUID.
    """
    from app.tools.events import get_event as _get_event

    return _get_event(get_misp_client(), event_id, include_attributes)


@mcp.tool()
async def search_events(
    limit: int = 10, days_back: int = None, date_from: str = None, date_to: str = None, org: str = None, tags: str = None, threat_level: int = None
) -> str:
    """
    Search for MISP events with various filters.
    """
    from app.tools.events import search_events as _search_events

    return _search_events(get_misp_client(), limit, days_back, date_from, date_to, org, tags, threat_level)


# Attribute management tools
@mcp.tool()
async def add_attribute(
    event_id: str, attribute_type: str, value: str, category: str, comment: str = None, to_ids: bool = False, distribution: int = 5
) -> str:
    """
    Add an attribute to a MISP event.
    """
    from app.tools.attributes import add_attribute as _add_attribute

    return _add_attribute(get_misp_client(), event_id, attribute_type, value, category, comment, to_ids, distribution)


@mcp.tool()
async def get_event_attributes(event_id: str, limit: int = 20, attribute_type: str = None, category: str = None) -> str:
    """
    Get all attributes for a specific MISP event.
    """
    from app.tools.attributes import get_event_attributes as _get_event_attributes

    return _get_event_attributes(get_misp_client(), event_id, limit, attribute_type, category)


# Resources
@mcp.resource("events://recent/{days}")
async def get_recent_events(days: int = 7) -> str:
    """Get recent MISP events from the last N days."""
    from app.resources.events import get_recent_events as _get_recent_events

    return _get_recent_events(get_misp_client(), days)


@mcp.resource("feeds://")
async def get_feeds() -> str:
    """Get information about recent MISP feeds."""
    from app.resources.feeds import get_feeds as _get_feeds

    return _get_feeds(get_misp_client())


async def main():
    try:
        # Initialize MISP client
        get_misp_client()

        # Test connection on startup
        result = misp_client.test_connection()
        if result["status"] == "connected":
            logger.info(f"✅ Successfully connected to MISP: {result.get('version')}")
        else:
            logger.warning(f"⚠️ MISP connection test failed: {result.get('message')}")

        # Run the server
        logger.info("🚀 Starting MISP MCP Server with FastMCP...")
        await mcp.run_async(transport="http", host=settings.mcp_server_host, port=settings.mcp_server_port)

    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MISP MCP Server stopped")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        exit(1)
