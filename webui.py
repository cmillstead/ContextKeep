#!/usr/bin/env python3
"""
ContextKeep V1.2 - WebUI Server
Provides a modern web interface for memory management
"""

from flask import Flask, render_template, jsonify, request
from pathlib import Path
import json
import logging
import os
import secrets
import sys

# Add parent directory to path to import memory_manager
sys.path.insert(0, str(Path(__file__).parent))
from core.memory_manager import memory_manager
from core.content_scanner import scan_content

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# CSRF token (module-level, stable for app lifetime)
_csrf_token = secrets.token_hex(32)

logger = logging.getLogger(__name__)


# ─── Security Middleware ───


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; font-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return response


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "DELETE"):
        token = request.headers.get("X-CSRF-Token", "")
        if token != _csrf_token:
            return jsonify({"success": False, "error": "CSRF token invalid"}), 403


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"success": False, "error": "Request too large"}), 413


# ─── Routes ───


@app.route("/")
def index():
    """Serve the main WebUI page"""
    return render_template("index.html", csrf_token=_csrf_token)


@app.route("/api/memories", methods=["GET"])
def list_memories():
    """Get all memories"""
    try:
        memories = memory_manager.list_memories()
        return jsonify({"success": True, "memories": memories})
    except Exception:
        logger.exception("Error listing memories")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/memories/<key>", methods=["GET"])
def get_memory(key):
    """Get a specific memory by key"""
    try:
        memory = memory_manager.retrieve_memory(key)
        if memory:
            return jsonify({"success": True, "memory": memory})
        return jsonify({"success": False, "error": "Memory not found"}), 404
    except Exception:
        logger.exception("Error retrieving memory")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/memories", methods=["POST"])
def create_memory():
    """Create a new memory"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Request body is required"}), 400

        key = data.get("key", "")
        title = data.get("title", "")
        content = data.get("content", "")
        tags = data.get("tags", [])

        if not key:
            return jsonify({"success": False, "error": "Key is required"}), 400

        scan = scan_content(content)

        result = memory_manager.store_memory(
            key, content, tags, title,
            source="human", created_by="webui",
            suspicious=scan["suspicious"],
            matched_patterns=scan["matched_patterns"],
            audit_entry="Created via WebUI",
        )
        return jsonify({"success": True, "memory": result})
    except Exception:
        logger.exception("Error creating memory")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/memories/<key>", methods=["PUT"])
def update_memory(key):
    """Update a memory (including title)"""
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Request body is required"}), 400

        content = data.get("content", "")
        title = data.get("title", "")
        tags = data.get("tags", [])
        action = data.get("action", "Manual Edit")

        # Check immutability — allow only immutability toggle, block content changes
        existing = memory_manager.retrieve_memory(key)
        if existing and existing.get("immutable"):
            is_toggle_only = "immutable" in data and not data["immutable"]
            if not is_toggle_only:
                return jsonify({"success": False, "error": "Memory is immutable (LOCKED). Unlock it first."}), 403
            # Handle immutable toggle only
            memory_manager.set_immutable(key, False)
            result = memory_manager.retrieve_memory(key)
            return jsonify({"success": True, "memory": result})

        scan = scan_content(content)

        result = memory_manager.store_memory(
            key, content, tags, title,
            source="human", created_by="webui",
            suspicious=scan["suspicious"],
            matched_patterns=scan["matched_patterns"],
            audit_entry=f"{action} via WebUI",
        )

        # Handle immutable toggle
        if "immutable" in data:
            updated = memory_manager.set_immutable(key, bool(data["immutable"]))
            if updated:
                result["immutable"] = updated["immutable"]

        return jsonify({"success": True, "memory": result})
    except Exception:
        logger.exception("Error updating memory")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/memories/<key>", methods=["DELETE"])
def delete_memory(key):
    """Delete a memory"""
    try:
        # Check immutability
        existing = memory_manager.retrieve_memory(key)
        if existing and existing.get("immutable"):
            return jsonify({"success": False, "error": "Memory is immutable (LOCKED). Unlock it first."}), 403

        success = memory_manager.delete_memory(key)
        if success:
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Memory not found"}), 404
    except Exception:
        logger.exception("Error deleting memory")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/search", methods=["GET"])
def search_memories():
    """Search memories"""
    try:
        query = request.args.get("q", "")
        results = memory_manager.search_memories(query)
        return jsonify({"success": True, "memories": results})
    except Exception:
        logger.exception("Error searching memories")
        return jsonify({"success": False, "error": "Internal server error"}), 500


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    print("Starting ContextKeep V1.2 WebUI...")
    print("Access at: http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
