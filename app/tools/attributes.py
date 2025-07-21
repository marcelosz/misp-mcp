from typing import Optional
import logging

from pymisp import MISPAttribute

from app.misp.client import MISPClient

logger = logging.getLogger(__name__)


def add_attribute(
    misp_client: MISPClient,
    event_id: str,
    attribute_type: str,
    value: str,
    category: str,
    comment: Optional[str] = None,
    to_ids: bool = False,
    distribution: int = 5,
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

    try:
        attribute = MISPAttribute()
        attribute.type = attribute_type
        attribute.value = value
        attribute.category = category
        attribute.to_ids = to_ids
        attribute.distribution = distribution

        if comment:
            attribute.comment = comment

        result = misp_client.client.add_attribute(event_id, attribute)

        if "Attribute" in result:
            attr_data = result["Attribute"]
            return f"""✅ **Attribute Added Successfully!**

**Attribute Details:**
- Attribute ID: {attr_data.get("id")}
- Event ID: {attr_data.get("event_id")}
- Type: {attr_data.get("type")}
- Value: {attr_data.get("value")}
- Category: {attr_data.get("category")}
- To IDS: {"Yes" if attr_data.get("to_ids") else "No"}
- Distribution: {attr_data.get("distribution")} ({_get_distribution_name(attr_data.get("distribution"))})
- Comment: {attr_data.get("comment", "None")}
- Created: {attr_data.get("timestamp")}

**Usage:**
This attribute can now be used for correlation and detection within MISP."""
        else:
            return f"❌ Failed to add attribute. Response: {result}"

    except Exception as e:
        logger.error(f"Failed to add attribute to event {event_id}: {e}")
        return f"""❌ **Failed to add attribute.**

**Event ID:** {event_id}
**Attribute Type:** {attribute_type}
**Value:** {value}
**Error:** {str(e)}

Please check your input parameters and ensure the event exists."""


def get_event_attributes(
    misp_client: MISPClient,
    event_id: str,
    limit: int = 20,
    attribute_type: Optional[str] = None,
    category: Optional[str] = None,
) -> str:
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

    try:
        # Limit results for performance
        limit = min(limit, 100)

        # Get the event with attributes
        event = misp_client.client.get_event(event_id, pythonify=True)

        if not hasattr(event, "attributes"):
            return f"❌ Event {event_id} not found or has no attributes."

        attributes = event.attributes

        # Apply filters
        if attribute_type:
            attributes = [attr for attr in attributes if attr.type == attribute_type]

        if category:
            attributes = [attr for attr in attributes if attr.category == category]

        if not attributes:
            filter_text = ""
            if attribute_type or category:
                filters = []
                if attribute_type:
                    filters.append(f"type='{attribute_type}'")
                if category:
                    filters.append(f"category='{category}'")
                filter_text = f" matching filters: {', '.join(filters)}"

            return f"📭 No attributes found for event {event_id}{filter_text}."

        # Limit results
        attributes = attributes[:limit]

        output = f"""📋 **Event {event_id} Attributes ({len(attributes)} shown):**

**Event Info:** {event.info}
"""

        # Group attributes by category for better readability
        categories = {}
        for attr in attributes:
            cat = attr.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(attr)

        for category_name, cat_attributes in categories.items():
            output += f"\n**{category_name} ({len(cat_attributes)}):**"
            for attr in cat_attributes:
                ids_indicator = "🛡️" if attr.to_ids else "📝"
                output += f"\n  {ids_indicator} {attr.type}: {attr.value}"
                if hasattr(attr, "comment") and attr.comment:
                    output += f" ({attr.comment})"

        if len(event.attributes) > limit:
            output += f"\n\n⚠️ Showing {limit} of {len(event.attributes)} total attributes. Use filters or increase limit to see more."

        output += "\n\n**Legend:**\n🛡️ = IDS detection enabled\n📝 = Information only"

        return output

    except Exception as e:
        logger.error(f"Failed to get attributes for event {event_id}: {e}")
        return f"""❌ **Failed to retrieve event attributes.**

**Event ID:** {event_id}
**Error:** {str(e)}

Please verify the event ID and your access permissions."""


def _get_distribution_name(dist_id: int) -> str:
    """Convert distribution ID to readable name."""
    distribution_map = {
        0: "Your Organization Only",
        1: "This Community Only",
        2: "Connected Communities",
        3: "All Communities",
        5: "Inherit from Event",
    }
    return distribution_map.get(dist_id, f"Unknown ({dist_id})")


# Common MISP attribute types for reference
COMMON_ATTRIBUTE_TYPES = {
    "Network": ["ip-src", "ip-dst", "domain", "hostname", "url", "uri", "user-agent"],
    "Files": ["filename", "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash"],
    "Email": ["email-src", "email-dst", "email-subject", "email-attachment"],
    "Registry": ["regkey", "regkey|value"],
    "Other": ["text", "comment", "other", "vulnerability", "target-user"],
}

COMMON_CATEGORIES = [
    "Antivirus detection",
    "Artifacts dropped",
    "Attribution",
    "External analysis",
    "Financial fraud",
    "Internal reference",
    "Network activity",
    "Other",
    "Payload delivery",
    "Payload installation",
    "Payload type",
    "Persistence mechanism",
    "Person",
    "Social network",
    "Support Tool",
    "Targeting data",
]
