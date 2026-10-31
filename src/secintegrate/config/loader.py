"""Read connector files from disk."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .schema import ConnectorConfig


def config_files(directory: str | Path) -> list[Path]:
    d = Path(directory)
    return sorted([*d.glob("*.yaml"), *d.glob("*.yml")]) if d.is_dir() else []


def read_yaml(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def parse_config(path: str | Path) -> ConnectorConfig:
    """Parse without validation messages. Callers run the validator first."""
    return ConnectorConfig.model_validate(read_yaml(path))


def find_connector_file(directory: str | Path, connector: str) -> Path | None:
    for f in config_files(directory):
        try:
            data = read_yaml(f)
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and data.get("connector") == connector:
            return f
    return None
