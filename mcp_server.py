#!/usr/bin/env python3
"""
MCP Server for Astra Scanner Tool

This server provides tools to interact with the Astra Linux Shodan scanner,
including running scans, listing results, and querying scan data.
"""

import asyncio
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        Tool,
        TextContent,
        ImageContent,
        EmbeddedResource,
        LoggingLevel,
        McpError,
        ErrorCode,
    )
except ImportError:
    # Fallback for different MCP package structure
    try:
        from mcp import Server, stdio_server
        from mcp.types import Tool, TextContent, McpError, ErrorCode
    except ImportError:
        raise ImportError(
            "MCP package not found. Install with: pip install mcp\n"
            "Or try: pip install anthropic-mcp"
        )


# Configuration
SCAN_RESULTS_DIR = Path("/home/codonnell/development/git/ai-shodan-astra-scan/tmp/shodan_results")
DOCKER_IMAGE = "astra-scanner:latest"
DOCKER_VOLUME_MOUNT = "/home/codonnell/development/git/ai-shodan-astra-scan/tmp/:/app/"


class AstraScannerServer:
    def __init__(self):
        self.server = Server("astra-scanner")
        self._setup_tools()

    def _setup_tools(self):
        """Register all MCP tools with the server."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools."""
            return [
                Tool(
                    name="run_scan",
                    description="Run a new Astra Linux scan using Shodan. API key can be provided as parameter, or set in MCP config env section, or as SHODAN_API_KEY environment variable.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "shodan_api_key": {
                                "type": "string",
                                "description": "Shodan API key for authentication (optional if set in config or environment)"
                            }
                        },
                        "required": []
                    }
                ),
                Tool(
                    name="list_scans",
                    description="List all available scan results with timestamps and metadata.",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="get_scan_summary",
                    description="Get summary statistics for a specific scan by timestamp.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "timestamp": {
                                "type": "string",
                                "description": "Scan timestamp in format YYYYMMDD_HHMMSS (e.g., '20260112_181049')"
                            }
                        },
                        "required": ["timestamp"]
                    }
                ),
                Tool(
                    name="get_scan_results",
                    description="Get combined results for a specific scan by timestamp.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "timestamp": {
                                "type": "string",
                                "description": "Scan timestamp in format YYYYMMDD_HHMMSS"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of matches to return (default: all)",
                                "default": None
                            }
                        },
                        "required": ["timestamp"]
                    }
                ),
                Tool(
                    name="get_geo_data",
                    description="Get geolocation data for a specific scan by timestamp.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "timestamp": {
                                "type": "string",
                                "description": "Scan timestamp in format YYYYMMDD_HHMMSS"
                            },
                            "country": {
                                "type": "string",
                                "description": "Filter results by country name (optional)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: all)",
                                "default": None
                            }
                        },
                        "required": ["timestamp"]
                    }
                ),
                Tool(
                    name="get_latest_scan",
                    description="Get the most recent scan summary and basic statistics.",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="search_results",
                    description="Search across scan results by IP, country, city, or port.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip": {
                                "type": "string",
                                "description": "Search by IP address (optional)"
                            },
                            "country": {
                                "type": "string",
                                "description": "Search by country name (optional)"
                            },
                            "city": {
                                "type": "string",
                                "description": "Search by city name (optional)"
                            },
                            "port": {
                                "type": "integer",
                                "description": "Search by port number (optional)"
                            },
                            "timestamp": {
                                "type": "string",
                                "description": "Limit search to specific scan timestamp (optional)"
                            }
                        },
                        "required": []
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool calls."""
            
            if name == "run_scan":
                return await self._run_scan(arguments)
            elif name == "list_scans":
                return await self._list_scans()
            elif name == "get_scan_summary":
                return await self._get_scan_summary(arguments)
            elif name == "get_scan_results":
                return await self._get_scan_results(arguments)
            elif name == "get_geo_data":
                return await self._get_geo_data(arguments)
            elif name == "get_latest_scan":
                return await self._get_latest_scan()
            elif name == "search_results":
                return await self._search_results(arguments)
            else:
                raise McpError(
                    ErrorCode.METHOD_NOT_FOUND,
                    f"Unknown tool: {name}"
                )

    async def _run_scan(self, args: dict[str, Any]) -> list[TextContent]:
        """Run a new scan using Docker."""
        # Try to get API key from multiple sources (in order of preference):
        # 1. Parameter passed to tool
        # 2. Environment variable
        # 3. From MCP server environment (if set in config)
        api_key = args.get("shodan_api_key")
        if not api_key:
            api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise McpError(
                ErrorCode.INVALID_PARAMS,
                "shodan_api_key is required. Provide it as a parameter, set SHODAN_API_KEY environment variable, or add it to MCP config env section."
            )

        # Build Docker command
        cmd = [
            "docker", "run", "--rm", "-it",
            "-e", f"SHODAN_API_KEY={api_key}",
            "-v", DOCKER_VOLUME_MOUNT,
            DOCKER_IMAGE
        ]

        try:
            # Run the scan (remove -it flags for non-interactive execution)
            cmd_modified = [c for c in cmd if c not in ["-it", "-i", "-t"]]
            process = await asyncio.create_subprocess_exec(
                *cmd_modified,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(SCAN_RESULTS_DIR.parent)
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return [TextContent(
                    type="text",
                    text=f"Scan failed with error:\n{error_msg}"
                )]
            
            output = stdout.decode() if stdout else ""
            
            # Try to find the timestamp from the output or latest file
            latest_scan = self._get_latest_scan_timestamp()
            
            return [TextContent(
                type="text",
                text=f"Scan completed successfully!\n\n{output}\n\nLatest scan timestamp: {latest_scan}"
            )]
            
        except Exception as e:
            raise McpError(
                ErrorCode.INTERNAL_ERROR,
                f"Failed to run scan: {str(e)}"
            )

    async def _list_scans(self) -> list[TextContent]:
        """List all available scans."""
        if not SCAN_RESULTS_DIR.exists():
            return [TextContent(
                type="text",
                text="No scan results directory found."
            )]

        summaries = []
        for file in sorted(SCAN_RESULTS_DIR.glob("scan_summary_*.json"), reverse=True):
            timestamp = file.stem.replace("scan_summary_", "")
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    summaries.append({
                        "timestamp": timestamp,
                        "queries_executed": data.get("queries_executed", 0),
                        "total_matches": data.get("total_matches", 0),
                        "unique_ips": data.get("unique_ips", 0),
                        "countries_found": data.get("countries_found", 0)
                    })
            except Exception as e:
                summaries.append({
                    "timestamp": timestamp,
                    "error": f"Failed to read: {str(e)}"
                })

        if not summaries:
            return [TextContent(
                type="text",
                text="No scan results found."
            )]

        result = "Available Scans:\n" + "=" * 80 + "\n"
        for summary in summaries:
            if "error" in summary:
                result += f"\nTimestamp: {summary['timestamp']}\n  Error: {summary['error']}\n"
            else:
                result += f"\nTimestamp: {summary['timestamp']}\n"
                result += f"  Queries: {summary['queries_executed']}\n"
                result += f"  Total Matches: {summary['total_matches']}\n"
                result += f"  Unique IPs: {summary['unique_ips']}\n"
                result += f"  Countries: {summary['countries_found']}\n"

        return [TextContent(type="text", text=result)]

    async def _get_scan_summary(self, args: dict[str, Any]) -> list[TextContent]:
        """Get summary for a specific scan."""
        timestamp = args.get("timestamp")
        if not timestamp:
            raise McpError(ErrorCode.INVALID_PARAMS, "timestamp is required")

        summary_file = SCAN_RESULTS_DIR / f"scan_summary_{timestamp}.json"
        if not summary_file.exists():
            return [TextContent(
                type="text",
                text=f"Scan summary not found for timestamp: {timestamp}"
            )]

        try:
            with open(summary_file, 'r') as f:
                data = json.load(f)
            
            result = json.dumps(data, indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            raise McpError(
                ErrorCode.INTERNAL_ERROR,
                f"Failed to read summary: {str(e)}"
            )

    async def _get_scan_results(self, args: dict[str, Any]) -> list[TextContent]:
        """Get combined results for a specific scan."""
        timestamp = args.get("timestamp")
        limit = args.get("limit")
        
        if not timestamp:
            raise McpError(ErrorCode.INVALID_PARAMS, "timestamp is required")

        results_file = SCAN_RESULTS_DIR / f"combined_results_{timestamp}.json"
        if not results_file.exists():
            return [TextContent(
                type="text",
                text=f"Scan results not found for timestamp: {timestamp}"
            )]

        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            matches = data.get("all_matches", [])
            if limit:
                matches = matches[:limit]
                data["all_matches"] = matches
                data["_note"] = f"Limited to {limit} matches"
            
            result = json.dumps(data, indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            raise McpError(
                ErrorCode.INTERNAL_ERROR,
                f"Failed to read results: {str(e)}"
            )

    async def _get_geo_data(self, args: dict[str, Any]) -> list[TextContent]:
        """Get geolocation data for a specific scan."""
        timestamp = args.get("timestamp")
        country = args.get("country")
        limit = args.get("limit")
        
        if not timestamp:
            raise McpError(ErrorCode.INVALID_PARAMS, "timestamp is required")

        geo_file = SCAN_RESULTS_DIR / f"geo_data_{timestamp}.json"
        if not geo_file.exists():
            return [TextContent(
                type="text",
                text=f"Geo data not found for timestamp: {timestamp}"
            )]

        try:
            with open(geo_file, 'r') as f:
                data = json.load(f)
            
            # Filter by country if specified
            if country:
                data = [item for item in data if item.get("country", "").lower() == country.lower()]
            
            # Apply limit
            if limit:
                data = data[:limit]
            
            result = json.dumps(data, indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            raise McpError(
                ErrorCode.INTERNAL_ERROR,
                f"Failed to read geo data: {str(e)}"
            )

    async def _get_latest_scan(self) -> list[TextContent]:
        """Get the most recent scan summary."""
        latest_timestamp = self._get_latest_scan_timestamp()
        if not latest_timestamp:
            return [TextContent(
                type="text",
                text="No scan results found."
            )]

        summary_file = SCAN_RESULTS_DIR / f"scan_summary_{latest_timestamp}.json"
        if not summary_file.exists():
            return [TextContent(
                type="text",
                text=f"Latest scan summary not found for timestamp: {latest_timestamp}"
            )]

        try:
            with open(summary_file, 'r') as f:
                data = json.load(f)
            
            result = f"Latest Scan (Timestamp: {latest_timestamp})\n"
            result += "=" * 80 + "\n"
            result += json.dumps(data, indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            raise McpError(
                ErrorCode.INTERNAL_ERROR,
                f"Failed to read latest scan: {str(e)}"
            )

    async def _search_results(self, args: dict[str, Any]) -> list[TextContent]:
        """Search across scan results."""
        ip = args.get("ip")
        country = args.get("country")
        city = args.get("city")
        port = args.get("port")
        timestamp = args.get("timestamp")

        # Determine which scan(s) to search
        if timestamp:
            scan_files = [SCAN_RESULTS_DIR / f"combined_results_{timestamp}.json"]
        else:
            scan_files = list(SCAN_RESULTS_DIR.glob("combined_results_*.json"))

        if not scan_files:
            return [TextContent(
                type="text",
                text="No scan results found."
            )]

        results = []
        for scan_file in scan_files:
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                
                matches = data.get("all_matches", [])
                for match in matches:
                    # Apply filters
                    if ip and match.get("ip_str") != ip:
                        continue
                    if country and match.get("location", {}).get("country_name", "").lower() != country.lower():
                        continue
                    if city and match.get("location", {}).get("city", "").lower() != city.lower():
                        continue
                    if port is not None and match.get("port") != port:
                        continue
                    
                    results.append(match)
            except Exception as e:
                continue

        if not results:
            return [TextContent(
                type="text",
                text="No matches found for the specified criteria."
            )]

        result_data = {
            "total_matches": len(results),
            "matches": results
        }
        result = json.dumps(result_data, indent=2)
        return [TextContent(type="text", text=result)]

    def _get_latest_scan_timestamp(self) -> Optional[str]:
        """Get the timestamp of the most recent scan."""
        if not SCAN_RESULTS_DIR.exists():
            return None

        summary_files = list(SCAN_RESULTS_DIR.glob("scan_summary_*.json"))
        if not summary_files:
            return None

        # Sort by modification time
        latest_file = max(summary_files, key=lambda p: p.stat().st_mtime)
        return latest_file.stem.replace("scan_summary_", "")


async def main():
    """Main entry point for the MCP server."""
    server_instance = AstraScannerServer()
    
    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await server_instance.server.run(
            read_stream,
            write_stream,
            server_instance.server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
