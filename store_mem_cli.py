#!/usr/bin/env python3
"""CLI utility to store a memory directly (for testing/scripting)."""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from core.memory_manager import memory_manager
from core.encryption import is_encryption_enabled


def store_example():
    """Store an example memory for testing."""
    key = "example_project_state"
    title = "Example Project State"
    tags = ["example", "test"]
    content = """Example project memory.
Location: /path/to/your/project
Status: Active
Tech Stack: Python, Flask"""

    try:
        result = memory_manager.store_memory(key, content, tags, title,
                                              source="cli", created_by="cli")
        print(f"SUCCESS: Stored memory '{result['title']}'")
    except Exception as e:
        print(f"ERROR: {e}")


def encrypt_existing():
    """Encrypt all unencrypted memories."""
    if not is_encryption_enabled():
        print("ERROR: CONTEXTKEEP_SECRET not set. Cannot encrypt.")
        sys.exit(1)
    memories = memory_manager.list_memories()
    count = 0
    for mem in memories:
        if not mem.get("encrypted"):
            memory_manager.store_memory(
                mem["key"], mem["content"], mem.get("tags", []), mem.get("title"),
                source=mem.get("source", "unknown"),
                created_by=mem.get("created_by", "unknown"),
                force=True,
            )
            count += 1
    print(f"Encrypted {count} memories.")


def decrypt_existing():
    """Decrypt all encrypted memories."""
    if not is_encryption_enabled():
        print("ERROR: CONTEXTKEEP_SECRET not set. Cannot decrypt.")
        sys.exit(1)
    import os
    memories = memory_manager.list_memories()
    # Pop secret ONCE before the loop — store_memory without encryption
    secret = os.environ.pop("CONTEXTKEEP_SECRET")
    count = 0
    try:
        for mem in memories:
            if mem.get("encrypted"):
                memory_manager.store_memory(
                    mem["key"], mem["content"], mem.get("tags", []), mem.get("title"),
                    source=mem.get("source", "unknown"),
                    created_by=mem.get("created_by", "unknown"),
                    force=True,
                )
                count += 1
    finally:
        os.environ["CONTEXTKEEP_SECRET"] = secret
    print(f"Decrypted {count} memories.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ContextKeep CLI Utility")
    parser.add_argument("--encrypt-existing", action="store_true",
                        help="Encrypt all unencrypted memories")
    parser.add_argument("--decrypt-existing", action="store_true",
                        help="Decrypt all encrypted memories")
    args = parser.parse_args()

    if args.encrypt_existing:
        encrypt_existing()
    elif args.decrypt_existing:
        decrypt_existing()
    else:
        store_example()
