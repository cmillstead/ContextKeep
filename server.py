#!/usr/bin/env python3
"""
ContextKeep V1.2 - MCP Server
Exposes memory tools to IDEs (VS Code, Cursor, etc.)
"""

import asyncio
import sys
import json
import os
import hashlib
import logging
import argparse
from fastmcp import FastMCP
from core.memory_manager import memory_manager
from core.content_scanner import scan_all_fields
from core.utils import RateLimiter as _RateLimiter, _parse_max_size

logger = logging.getLogger("contextkeep")

# Initialize FastMCP
mcp = FastMCP("context-keep")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_CONTENT_SIZE = _parse_max_size()
RATE_LIMIT_WRITES = 20   # per minute
RATE_LIMIT_WINDOW = 60   # seconds

_write_limiter = _RateLimiter(max_calls=RATE_LIMIT_WRITES, window=RATE_LIMIT_WINDOW)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _provenance_flags(mem: dict) -> str:
    """Return provenance flag string for display."""
    flags = []
    if mem.get("immutable"):
        flags.append("LOCKED")
    if mem.get("suspicious"):
        flags.append("SUSPICIOUS")
    return f" [{', '.join(flags)}]" if flags else ""


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def store_memory(key: str, content: str, tags: str = "", title: str = "") -> str:
    """
    Store a new memory or update an existing one.

    Args:
        key: Unique identifier for the memory (e.g., "project_notes", "meeting_2023-10-27")
        content: The actual content of the memory.
        tags: Comma-separated list of tags (optional).
        title: Human-readable title (optional).
    """
    logger.debug("store_memory called for key='%s'", key)

    # --- Gate: rate limit ---
    if not _write_limiter.allow():
        logger.warning("Rate limit exceeded for store_memory key='%s'", key)
        return "Rate limit exceeded (max %d writes/min). Try again later." % RATE_LIMIT_WRITES

    # --- Gate: content size ---
    content_bytes = len(content.encode("utf-8"))
    if content_bytes > MAX_CONTENT_SIZE:
        logger.warning("Content too large for key='%s' (%d bytes)", key, content_bytes)
        return "Content too large (max %d bytes)." % MAX_CONTENT_SIZE

    # --- Gate: immutability ---
    existing = memory_manager.retrieve_memory(key)
    if existing and existing.get("immutable"):
        logger.warning("Blocked write to immutable key='%s'", key)
        return "Memory '%s' is immutable (LOCKED). Cannot overwrite via MCP." % key

    # --- Content scanning ---
    tag_list = [t.strip() for t in tags.split(",")] if tags else []
    scan = scan_all_fields(key=key, title=title, tags=tag_list, content=content)
    if scan["suspicious"]:
        logger.warning("Suspicious content detected in key='%s': patterns=%s", key, scan["matched_patterns"])

    try:

        audit = "AI Update via MCP" if existing else "Created via MCP"

        result = memory_manager.store_memory(
            key,
            content,
            tag_list,
            title,
            source="mcp",
            created_by="mcp-tool",
            suspicious=scan["suspicious"],
            matched_patterns=scan["matched_patterns"],
            audit_entry=audit,
        )
        flags = _provenance_flags(result)
        logger.debug("store_memory success for key='%s'", key)
        return "Memory stored: '%s' (Key: %s) (%d chars)%s" % (
            result["title"], key, result["chars"], flags,
        )
    except Exception as e:
        logger.error("store_memory failed: %s", e)
        raise


@mcp.tool()
async def retrieve_memory(key: str) -> str:
    """
    Retrieve a memory by its key.

    Args:
        key: The unique identifier of the memory.
    """
    logger.debug("retrieve_memory called for key='%s'", key)
    try:
        result = memory_manager.retrieve_memory(key)
        if result:
            flags = _provenance_flags(result)
            logger.debug("retrieve_memory found key='%s'", key)
            return "Memory: %s%s\nKey: %s\nUpdated: %s\n\n%s" % (
                result.get("title", key), flags, result["key"],
                result["updated_at"], result["content"],
            )
        logger.debug("retrieve_memory NOT found key='%s'", key)
        return "Memory not found: '%s'" % key
    except Exception as e:
        logger.error("retrieve_memory failed: %s", e)
        raise


@mcp.tool()
async def search_memories(query: str) -> str:
    """
    Search for memories by key, title, or content.

    Args:
        query: The search term.
    """
    logger.debug("search_memories called for query='%s'", query)
    try:
        results = memory_manager.search_memories(query)
        if not results:
            logger.debug("search_memories found 0 results")
            return "No memories found for '%s'" % query

        logger.debug("search_memories found %d results", len(results))
        output = "Found %d memories for '%s':\n\n" % (len(results), query)
        for mem in results:
            title = mem.get("title", mem["key"])
            flags = _provenance_flags(mem)
            output += "- %s%s (Key: %s) (%s): %s\n" % (
                title, flags, mem["key"], mem["updated_at"][:16], mem["snippet"],
            )
        return output
    except Exception as e:
        logger.error("search_memories failed: %s", e)
        raise


@mcp.tool()
async def list_recent_memories() -> str:
    """List the 10 most recently updated memories."""
    logger.debug("list_recent_memories called")
    try:
        memories = memory_manager.list_memories()[:10]
        if not memories:
            logger.debug("list_recent_memories found 0 memories")
            return "No memories found."

        logger.debug("list_recent_memories found %d memories", len(memories))
        output = "Recent Memories:\n"
        for mem in memories:
            title = mem.get("title", mem["key"])
            flags = _provenance_flags(mem)
            output += "- %s%s (Key: %s) - %s\n" % (title, flags, mem["key"], mem["updated_at"][:16])
        return output
    except Exception as e:
        logger.error("list_recent_memories failed: %s", e)
        raise


@mcp.tool()
async def list_all_memories() -> str:
    """
    List ALL stored memories as a complete directory — keys, titles, tags, and last-updated timestamps.

    Use this as your FIRST step when you need to find a specific memory but are unsure of the
    exact key. Pick the correct key from this list, then call retrieve_memory(key) directly.
    This avoids unreliable fuzzy search and ensures accurate retrieval in one extra call.
    """
    logger.debug("list_all_memories called")
    try:
        memories = memory_manager.list_memories()
        if not memories:
            logger.debug("list_all_memories found 0 memories")
            return "No memories stored yet."

        logger.debug("list_all_memories found %d memories", len(memories))
        output = "Memory Directory — %d total memories:\n" % len(memories)
        output += "=" * 50 + "\n\n"
        for mem in memories:
            title = mem.get("title", mem["key"])
            tags = ", ".join(mem.get("tags", [])) if mem.get("tags") else "none"
            updated = mem.get("updated_at", "")[:16]
            flags = _provenance_flags(mem)
            output += "Key:     %s%s\n" % (mem["key"], flags)
            output += "   Title:   %s\n" % title
            output += "   Tags:    %s\n" % tags
            output += "   Updated: %s\n\n" % updated
        return output
    except Exception as e:
        logger.error("list_all_memories failed: %s", e)
        raise


@mcp.tool()
async def delete_memory(key: str, confirm: str) -> str:
    """
    Delete a memory permanently. Requires a confirmation code.

    Args:
        key: The unique identifier of the memory to delete.
        confirm: First 8 characters of sha256(key) as confirmation.
    """
    logger.debug("delete_memory called for key='%s'", key)

    expected = hashlib.sha256(key.encode()).hexdigest()[:8]
    if confirm != expected:
        return "Confirmation failed. To delete '%s', pass confirm='%s'." % (key, expected)

    # Check immutability
    existing = memory_manager.retrieve_memory(key)
    if existing and existing.get("immutable"):
        logger.warning("Blocked delete of immutable key='%s'", key)
        return "Memory '%s' is immutable (LOCKED). Cannot delete via MCP." % key

    deleted = memory_manager.delete_memory(key)
    if deleted:
        logger.info("Deleted memory key='%s'", key)
        return "Memory '%s' deleted." % key
    return "Memory not found: '%s'" % key


@mcp.tool()
async def mark_immutable(key: str) -> str:
    """
    Mark a memory as immutable (LOCKED). This is one-way via MCP — only the WebUI can unlock.

    Args:
        key: The unique identifier of the memory to lock.
    """
    logger.debug("mark_immutable called for key='%s'", key)

    existing = memory_manager.retrieve_memory(key)
    if existing is None:
        return "Memory not found: '%s'" % key

    if existing.get("immutable"):
        return "Memory '%s' is already immutable (LOCKED)." % key

    result = memory_manager.set_immutable(key, True)
    if result is None:
        return "Memory not found: '%s'" % key

    logger.info("Marked memory as immutable key='%s'", key)
    return "Memory '%s' is now immutable (LOCKED). Only the WebUI can unlock it." % key


# ---------------------------------------------------------------------------
# Logging & CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ContextKeep V1.2 - MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host for SSE transport (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=5100, help="Port for SSE transport (default: 5100)"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable DEBUG-level logging"
    )
    parser.add_argument(
        "--generate-config", action="store_true", help="Generate MCP configuration JSON"
    )

    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.generate_config:
        config = {
            "mcpServers": {
                "context-keep": {
                    "command": "python",
                    "args": [os.path.abspath(__file__)],
                }
            }
        }
        print(json.dumps(config, indent=2))
    else:
        if args.transport == "sse":
            logger.info(
                "Starting MCP server with SSE transport on %s:%s", args.host, args.port
            )
            mcp.run(transport="sse", host=args.host, port=args.port)
        else:
            logger.info("Starting MCP server with stdio transport")
            mcp.run(transport="stdio")
