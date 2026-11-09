"""Local JSON store for plans and apply runs (snapshots + change logs)."""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path


def home() -> Path:
    p = Path(os.environ.get("DOMAIN_SETUP_HOME", Path.home() / ".domain-setup-mcp"))
    (p / "plans").mkdir(parents=True, exist_ok=True)
    (p / "runs").mkdir(parents=True, exist_ok=True)
    return p


def new_id(prefix: str) -> str:
    return f"{prefix}_{time.strftime('%Y%m%d-%H%M%S')}_{secrets.token_hex(3)}"


def save(kind: str, obj_id: str, data: dict) -> Path:
    path = home() / kind / f"{obj_id}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def load(kind: str, obj_id: str) -> dict:
    if "/" in obj_id or ".." in obj_id:
        raise ValueError("Invalid id.")
    path = home() / kind / f"{obj_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No {kind[:-1]} with id {obj_id}. Run domain_plan first.")
    return json.loads(path.read_text())
