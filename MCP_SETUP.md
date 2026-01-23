# MCP Server Setup for Astra Scanner

This directory contains an MCP (Model Context Protocol) server that provides tools to interact with the Astra Linux Shodan scanner.

## Prerequisites

1. Python 3.8 or higher
2. Docker installed and running
3. The `astra-scanner:latest` Docker image built (see main README)
4. grep -r 'YOURUSER' * # change all of these to your user
5. MCP Python package installed

## Installation

### Option 1: Using Virtual Environment (Recommended)

1. Run the setup script to create a virtual environment and install dependencies:
```bash
chmod +x setup_mcp_venv.sh
./setup_mcp_venv.sh
```

This will:
- Create a `.venv` directory in your project
- Install all Python dependencies in the isolated environment
- Show you the Python path to use in your Cursor configuration

2. The `mcp_config.json` file is already configured to use the virtual environment at `.venv/bin/python`

### Option 2: Manual Virtual Environment Setup

If you prefer to set it up manually:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Deactivate when done (optional)
deactivate
```

Then update your Cursor MCP configuration to use `.venv/bin/python` instead of `python3`.

### Option 3: System-wide Installation (Not Recommended)

If you prefer to install system-wide (not recommended):

```bash
pip install -r requirements.txt
```

Then use `python3` in your Cursor configuration.

### Make MCP Server Executable

```bash
chmod +x mcp_server.py
```

## Cursor Configuration

To use this MCP server with Cursor, you need to add it to Cursor's MCP configuration. The `mcp_config.json` file in this directory is just a **reference template** - you need to manually add this configuration to Cursor.

### Method 1: Using Cursor Settings UI (Recommended)

1. Open Cursor Settings:
   - Press `Ctrl+,` (or `Cmd+,` on macOS)
   - Or go to File → Preferences → Settings
2. Search for "MCP" or "Model Context Protocol"
3. Look for "MCP Servers" or similar setting
4. Click "Edit in settings.json" or add the configuration directly

### Method 2: Edit settings.json Directly

1. Open `~/.config/Cursor/User/settings.json`
2. Add the MCP configuration. The format depends on Cursor's current MCP implementation, but typically looks like:

```json
{
  "mcpServers": {
    "astra-scanner": {
      "command": "/home/YOURUSER/development/git/ai-shodan-astra-scan/.venv/bin/python",
      "args": [
        "/home/YOURUSER/development/git/ai-shodan-astra-scan/mcp_server.py"
      ],
      "env": {
        "SHODAN_API_KEY": "your_actual_shodan_api_key_here"
      }
    }
  }
}
```

**Note:** If Cursor uses a different format, check the `mcp_config.json` file in this directory as a reference, but you'll need to add it to Cursor's actual settings file, not leave it in the project directory.

### Configuration Details

- **command**: Path to Python interpreter
  - With virtual environment: `/home/YOURUSER/development/git/ai-shodan-astra-scan/.venv/bin/python`
  - Without virtual environment: `python3` (or full path like `/usr/bin/python3`)
- **args**: Path to the `mcp_server.py` file
- **env**: Environment variables. **Recommended:** Add your `SHODAN_API_KEY` here:
  ```json
  "env": {
    "SHODAN_API_KEY": "your_actual_api_key_here"
  }
  ```

### SHODAN API Key Configuration

You can provide your Shodan API key in **three ways** (in order of preference):

1. **In MCP Config (Recommended)** - Add it to the `env` section in your Cursor MCP settings:
   ```json
   "env": {
     "SHODAN_API_KEY": "your_api_key_here"
   }
   ```
   This keeps your API key in Cursor's configuration and you don't need to pass it each time.

2. **System Environment Variable** - Set it in your shell:
   ```bash
   export SHODAN_API_KEY=your_api_key_here
   ```
   Then restart Cursor so it picks up the environment variable.

3. **As Tool Parameter** - Pass it when calling the `run_scan` tool:
   - "Run a scan with API key: abc123xyz"
   - The tool will prompt you for the key if not set elsewhere

**Security Note:** The MCP config method is recommended as it keeps the key in Cursor's secure storage rather than in your shell environment or having to type it each time.

**Note:** The `mcp_config.json` template uses the virtual environment path. If you're not using a virtual environment, change the `command` to `python3`.

**Important:** 
- Update the path to `mcp_server.py` to match your actual installation path
- Ensure `python3` is in your PATH, or use the full path to Python
- After adding the configuration, **restart Cursor** for the changes to take effect
- The `mcp_config.json` file in this project is just a template - Cursor won't read it automatically

## Available Tools

The MCP server provides the following tools:

1. **run_scan** - Run a new Astra Linux scan using Shodan
   - Requires: `shodan_api_key` parameter
   - Executes the Docker container with the scanner

2. **list_scans** - List all available scan results with timestamps and metadata

3. **get_scan_summary** - Get summary statistics for a specific scan
   - Requires: `timestamp` (format: YYYYMMDD_HHMMSS)

4. **get_scan_results** - Get combined results for a specific scan
   - Requires: `timestamp`
   - Optional: `limit` to limit number of results

5. **get_geo_data** - Get geolocation data for a specific scan
   - Requires: `timestamp`
   - Optional: `country` filter, `limit`

6. **get_latest_scan** - Get the most recent scan summary

7. **search_results** - Search across scan results by IP, country, city, or port
   - Optional filters: `ip`, `country`, `city`, `port`, `timestamp`

## Usage Examples

Once configured in Cursor, you can use the tools through natural language:

- "Run a new scan with my Shodan API key"
- "List all available scans"
- "Get the summary for scan 20260112_181049"
- "Show me the latest scan results"
- "Search for results from Russia"
- "Find all results on port 22"

## Troubleshooting

1. **Docker not found**: Ensure Docker is installed and the `astra-scanner:latest` image exists
2. **Permission denied**: Make sure `mcp_server.py` is executable (`chmod +x mcp_server.py`)
3. **Path issues**: Update the paths in the configuration to match your system
4. **Python dependencies**: Run `pip install -r requirements.txt` if you get import errors

## Notes

- The scan results directory is hardcoded to `/home/YOURUSER/development/git/ai-shodan-astra-scan/tmp/shodan_results`
- To change this, modify the `SCAN_RESULTS_DIR` constant in `mcp_server.py`
- The Docker volume mount path is also hardcoded and may need adjustment for your system
