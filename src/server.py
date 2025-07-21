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
    python src/server.py
"""

import asyncio
import logging
from fastmcp import FastMCP
from .config import get_settings
from .misp.client import MISPClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create main MCP server instance
app = FastMCP("MISP MCP Server")

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


# Register all tools with dependency injection for MISP client

# Connection tools
@app.tool()
async def check_connection() -> str:
    """Test the connection to the MISP instance and verify authentication."""
    from .tools.connection import check_connection as _check_connection
    return await _check_connection(misp_client)


@app.tool()
async def get_version() -> str:
    """Get detailed version information from the MISP instance."""
    from .tools.connection import get_version as _get_version
    return await _get_version(misp_client)


# Event management tools
@app.tool()
async def create_event(
    info: str,
    distribution: int = 1,
    threat_level_id: int = 3,
    analysis: int = 0,
    date: str = None
) -> str:
    """Create a new MISP event with basic information."""
    from .tools.events import create_event as _create_event
    return await _create_event(misp_client, info, distribution, threat_level_id, analysis, date)


@app.tool()
async def get_event(event_id: str, include_attributes: bool = True) -> str:
    """Retrieve a MISP event by ID or UUID."""
    from .tools.events import get_event as _get_event
    return await _get_event(misp_client, event_id, include_attributes)


@app.tool()
async def search_events(
    limit: int = 10,
    days_back: int = None,
    date_from: str = None,
    date_to: str = None,
    org: str = None,
    tags: str = None,
    threat_level: int = None
) -> str:
    """Search for MISP events with various filters."""
    from .tools.events import search_events as _search_events
    return await _search_events(
        misp_client, limit, days_back, date_from, date_to, org, tags, threat_level
    )


# Attribute management tools
@app.tool()
async def add_attribute(
    event_id: str,
    attribute_type: str,
    value: str,
    category: str,
    comment: str = None,
    to_ids: bool = False,
    distribution: int = 5
) -> str:
    """Add an attribute to a MISP event."""
    from .tools.attributes import add_attribute as _add_attribute
    return await _add_attribute(
        misp_client, event_id, attribute_type, value, category, comment, to_ids, distribution
    )


@app.tool()
async def get_event_attributes(
    event_id: str,
    limit: int = 20,
    attribute_type: str = None,
    category: str = None
) -> str:
    """Get all attributes for a specific MISP event."""
    from .tools.attributes import get_event_attributes as _get_event_attributes
    return await _get_event_attributes(misp_client, event_id, limit, attribute_type, category)


# Resources
@app.resource("events/recent/{days}")
async def get_recent_events(days: str) -> str:
    """Get recent MISP events from the last N days."""
    from .resources.events import get_recent_events as _get_recent_events
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
        logger.info("🚀 MISP MCP Server starting...")
        await app.run_async()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


def run_server():
    """Console script entry point for the MISP MCP Server."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 MISP MCP Server stopped")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        exit(1)


if __name__ == "__main__":
    """Entry point when running directly."""
    run_server()
