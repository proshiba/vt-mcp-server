import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

from typing import Any
import argparse
import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP

from vtapi_a import VirusTotalAPI

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    filename=f"{CURR_DIR}/log/vt-mcp-server.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)

@dataclass
class AppContext:
    vtapi: VirusTotalAPI

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Manage application lifecycle with type-safe context"""
    logger.info("Starting VirusTotal API client...")
    vt_api_obj = await VirusTotalAPI.create()
    try:
        logger.info("start MCP server with VirusTotal API client")
        yield AppContext(vtapi=vt_api_obj)
    finally:
        # Cleanup on shutdown
        logger.info("Shutting down MCP Server")
        await vt_api_obj.close()

mcp = FastMCP("vt-mcp-server", lifespan=app_lifespan)
# mcp = FastMCP("vt-mcp-server")

def format_reputation(reputation: dict[str, Any]) -> str:
    """Format the reputation data into a readable string."""
    return f"""
- Malicious: {reputation.get('malicious', "N/A")}
- Suspicious: {reputation.get('suspicious', "N/A")}
- Undetected: {reputation.get('undetected', "N/A")}
- Harmless: {reputation.get('harmless', "N/A")}
- Timeout: {reputation.get('timeout', "N/A")}
"""

@mcp.tool()
async def get_ip_reputation(ip_address: str) -> str:
    """Get VirusTotal reputation for an IP address.

    Args:
        ip_address: IP address to check reputation for
    """
    logger.info(f"Received request for IP reputation: {ip_address}")
    ctx = mcp.get_context()
    api = ctx.request_context.lifespan_context.vtapi
    logger.info(f"debug: api_module: {str(api)}")
    response = await api.get_ip_reputation(ip_address)
    reputation = [format_reputation(response)]
    return "\n---\n".join(reputation)

@mcp.tool()
async def get_domain_reputation(domain: str) -> str:
    """Get VirusTotal reputation for an IP address.

    Args:
        domain: IP address to check reputation for
    """
    logger.info(f"Received request for IP reputation: {domain}")
    ctx = mcp.get_context()
    api = ctx.request_context.lifespan_context.vtapi
    logger.info(f"debug: api_module: {str(api)}")
    response = await api.get_domain_reputation(domain)
    reputation = [format_reputation(response)]
    return "\n---\n".join(reputation)

@mcp.tool()
async def get_url_reputation(url: str) -> str:
    """Get VirusTotal reputation for an IP address.

    Args:
        url: IP address to check reputation for
    """
    logger.info(f"Received request for IP reputation: {url}")
    ctx = mcp.get_context()
    api = ctx.request_context.lifespan_context.vtapi
    logger.info(f"debug: api_module: {str(api)}")
    response = await api.get_url_reputation(url)
    reputation = [format_reputation(response)]
    return "\n---\n".join(reputation)

@mcp.tool()
async def get_file_reputation(filehash: str) -> str:
    """Get VirusTotal reputation for an IP address.

    Args:
        filehash: IP address to check reputation for
    """
    logger.info(f"Received request for IP reputation: {filehash}")
    ctx = mcp.get_context()
    api = ctx.request_context.lifespan_context.vtapi
    logger.info(f"debug: api_module: {str(api)}")
    response = await api.get_file_reputation(filehash)
    reputation = [format_reputation(response)]
    return "\n---\n".join(reputation)

def get_argments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the weather MCP server.")
    parser.add_argument("--transport", choices=["streamable-http", "sse", "stdio"], default="sse", help="Transport method for the server")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on (only for sse transport)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to run the server on (only for sse transport)")
    return parser.parse_args()

def main(transport: str, port: int, host: str) -> None:
    """Main function to run the MCP server."""
    if transport == "sse":
        print(f"Running MCP server on {host}:{port} using SSE transport...")
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.run(transport='sse')
    elif transport == "streamable-http":
        mcp.settings.host = host
        mcp.settings.port = port
        mcp.run(transport='streamable-http')
    elif transport == "stdio":
        mcp.run(transport='stdio')
    else:
        raise ValueError("Unsupported transport method. Use 'sse' or 'stdio'.")

if __name__ == "__main__":
    # Initialize and run the server
    args = get_argments()
    main(args.transport, args.port, args.host)
