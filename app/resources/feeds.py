import logging

from app.misp.client import MISPClient

logger = logging.getLogger(__name__)


def get_feeds(misp_client: MISPClient) -> str:
    """
    Get information about MISP feeds.

    Args:
        misp_client: The MISP client instance

    Returns:
        Formatted information about MISP feeds
    """
    try:
        # Get all feeds
        feeds = misp_client.client.feeds()

        # Format the output
        output = "MISP Feed Information:\n\n"

        enabled_feeds = []
        disabled_feeds = []

        for feed in feeds:
            feed_data = feed.get("Feed", feed) if isinstance(feed, dict) else feed

            # Separate enabled and disabled feeds
            if feed_data.get("enabled") == "0" or feed_data.get("enabled") is False:
                disabled_feeds.append(feed_data)
                continue

            enabled_feeds.append(feed_data)

            output += f"Name: {feed_data.get('name', 'Unnamed Feed')}\n"
            output += f"Provider: {feed_data.get('provider', 'Unknown')}\n"
            output += f"Source Format: {feed_data.get('source_format', 'Unknown')}\n"
            output += f"URL: {feed_data.get('url', 'N/A')}\n"
            output += f"Input Source: {feed_data.get('input_source', 'Unknown')}\n"
            output += f"Enabled: {'Yes' if feed_data.get('enabled') != '0' else 'No'}\n"
            output += f"Caching Enabled: {'Yes' if feed_data.get('caching_enabled') != '0' else 'No'}\n"
            if feed_data.get("description"):
                output += f"Description: {feed_data.get('description')}\n"

            output += "\n---\n\n"

        # Add summary
        total_feeds = len(enabled_feeds) + len(disabled_feeds)
        output += "Summary:\n"
        output += f"- Total Feeds: {total_feeds}\n"
        output += f"- Enabled Feeds: {len(enabled_feeds)}\n"
        output += f"- Disabled Feeds: {len(disabled_feeds)}\n"

        return output

    except Exception as e:
        logger.error(f"Failed to get MISP feeds: {e}")
        return f"Error fetching MISP feeds: {str(e)}"
