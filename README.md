# MISP MCP Server

A Model Context Protocol (MCP) server that enables Large Language Models to interact with MISP (Malware Information Sharing Platform) instances for threat intelligence operations.

## Features

### 🔧 Core Tools
- **check_connection**: Test MISP connectivity and authentication
- **get_version**: Retrieve MISP instance version information
- **create_event**: Create new MISP events with detailed information
- **get_event**: Fetch events by ID/UUID with attributes
- **search_events**: Search events with comprehensive filters
- **add_attribute**: Add attributes to events with full categorization
- **get_event_attributes**: Retrieve event attributes with filtering options

### 📊 Resources
- **events/recent/7**: Recent events from last 7 days
- **events/recent/30**: Recent events from last 30 days

## Quick Start

### 1. Prerequisites
- Python 3.12+
- Access to a MISP instance with API key
- `uv` package manager (recommended)

### 2. Installation

```bash
# Clone the repository
git clone <repository-url>
cd misp-mcp

# Install dependencies with uv (recommended)
uv sync

# Or install manually
uv install
```

### 3. Configuration

Create a `.env` file in the project root with your MISP instance details:

```env
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your-api-key-here
MISP_VERIFY_SSL=true
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
```

### 4. Running the Server

```bash
./run_server.sh
```
The script will:
- Check dependencies and install UV if needed
- Verify environment configuration
- Install/sync dependencies automatically
- Start the server


## Usage Examples

### Basic Event Management

```python
# Test connection
await check_connection()

# Create a new event
await create_event(
    info="Suspicious phishing campaign targeting finance sector",
    threat_level_id=2,  # Medium threat
    distribution=1,     # This community only
    analysis=0         # Initial analysis
)

# Search recent events
await search_events(limit=5, days_back=7)

# Get specific event details
await get_event(event_id="123", include_attributes=True)

# Add an attribute to an event
await add_attribute(
    event_id="123",
    attribute_type="domain",
    value="malicious-domain.com",
    category="Network activity",
    to_ids=True,
    comment="Identified in phishing campaign"
)
```

### Advanced Search Options

```python
# Search with multiple filters
await search_events(
    limit=20,
    days_back=30,
    org="MyOrganization",
    tags="phishing",
    threat_level=1  # High threat only
)

# Get event attributes with filtering
await get_event_attributes(
    event_id="123",
    limit=50,
    attribute_type="domain",
    category="Network activity"
)
```

### Resource Access

Access recent events through MCP resources:
- `events/recent/7` - Events from last 7 days
- `events/recent/30` - Events from last 30 days

These resources return structured JSON data with event summaries and statistics.

## Dependencies

This project uses:
- **FastMCP**: MCP server framework
- **PyMISP**: Official MISP Python library
- **Pydantic Settings**: Configuration management
- **Python-dotenv**: Environment variable handling

See `pyproject.toml` for complete dependency list and versions.

## Configuration Options

All configuration is handled through environment variables:

- `MISP_URL`: Your MISP instance URL (required)
- `MISP_API_KEY`: Your MISP API key (required)
- `MISP_VERIFY_SSL`: SSL certificate verification (default: true)
- `MCP_SERVER_HOST`: MCP server host (default: localhost)
- `MCP_SERVER_PORT`: MCP server port (default: 8000)

## Development

### Running in Development Mode

```bash
# Install with development dependencies
uv sync --group dev

# Run with auto-reload (if supported by your MCP client)
uv run python src/server.py
```

### Code Structure

- **Server**: Uses FastMCP framework for tool and resource registration
- **Client**: Wrapper around PyMISP for MISP API interactions  
- **Tools**: Async functions that perform MISP operations
- **Resources**: Endpoints that provide structured data access
- **Configuration**: Pydantic-based settings with environment variable support

### Adding New Features

1. Create tool functions in the appropriate module (`tools/`)
2. Register tools in `src/server.py` with dependency injection
3. Add comprehensive error handling and user-friendly output
4. Update this README with new functionality

## Troubleshooting

### Connection Issues
- Verify `MISP_URL` is accessible and includes the protocol (https://)
- Check that `MISP_API_KEY` is valid and has appropriate permissions
- Ensure SSL verification settings match your MISP instance configuration

### Installation Issues
- Make sure you have Python 3.12+ installed
- Try installing UV manually if the script fails: https://docs.astral.sh/uv/getting-started/installation/
- Use `uv sync` to ensure all dependencies are properly installed

### Server Startup Issues
- Check that the `.env` file exists and contains required variables
- Verify no other service is using the configured port
- Review logs for specific error messages

## Security

- All credentials are managed via environment variables
- SSL verification is configurable but recommended for production
- Input validation is implemented for all tools
- No credentials are logged or exposed in error messages
