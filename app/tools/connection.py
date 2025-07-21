import logging

from app.misp.client import MISPClient

logger = logging.getLogger(__name__)


async def check_connection(misp_client: MISPClient) -> str:
    """
    Test the connection to the MISP instance and verify authentication.
    """

    try:
        result = misp_client.test_connection()

        if result["status"] == "connected":
            return f"""✅ Successfully connected to MISP instance!

📊 **Connection Details:**
- Status: {result["status"]}
- MISP Version: {result.get("version", "unknown")}
- PyMISP Version: {result.get("pymisp_version", "unknown")}
- Server URL: {misp_client.settings.misp_url}
- SSL Verification: {"Enabled" if misp_client.settings.misp_verify_ssl else "Disabled"}"""
        else:
            return f"""❌ Failed to connect to MISP instance.

**Error Details:**
- Status: {result["status"]}
- Message: {result.get("message", "Unknown error")}
- Server URL: {misp_client.settings.misp_url}

Please check your MISP_URL and MISP_API_KEY configuration."""

    except Exception as e:
        logger.error(f"Connection check failed: {e}")
        return f"""❌ Connection check failed with exception.

**Error:** {str(e)}

Please verify your MISP configuration and network connectivity."""


async def get_version(misp_client: MISPClient) -> str:
    """
    Get detailed version information from the MISP instance.
    """

    try:
        version_info = misp_client.get_version()

        if isinstance(version_info, dict):
            return f"""📋 **MISP Version Information:**

**Core Versions:**
- MISP Version: {version_info.get("version", "unknown")}
- PyMISP Version: {version_info.get("pymisp_version", "unknown")}
- Application: {version_info.get("application", "unknown")}

**Additional Details:**
- API Version: {version_info.get("api_version", "unknown")}
- Modules: {len(version_info.get("modules", []))} available
- Taxonomies: {len(version_info.get("taxonomies", []))} loaded
- Galaxy Clusters: {len(version_info.get("galaxy_clusters", []))} available

**Server Information:**
- URL: {misp_client.settings.misp_url}
- SSL Verification: {"Enabled" if misp_client.settings.misp_verify_ssl else "Disabled"}"""
        else:
            return f"Version information received but format is unexpected: {version_info}"

    except Exception as e:
        logger.error(f"Failed to get version: {e}")
        return f"""❌ Failed to retrieve version information.

**Error:** {str(e)}

Please ensure you have a valid connection to the MISP instance."""
