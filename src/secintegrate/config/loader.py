"""Read connector files and substitute ${ENV} references."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..secrets import MissingSecret
from .schema import ConnectorConfig

ENV_REF = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


def expand_env(text: str, env: dict[str, str] | None = None) -> str:
    import os

    env = os.environ if env is None else env

    def sub(m: re.Match) -> str:
        value = env.get(m.group(1))
        if not value:
            raise MissingSecret(m.group(1))
        return value

    return ENV_REF.sub(sub, text) if isinstance(text, str) else text


def env_refs(text: Any) -> list[str]:
    return ENV_REF.findall(text) if isinstance(text, str) else []


def config_files(directory: str | Path) -> list[Path]:
    d = Path(directory)
    return sorted([*d.glob("*.yaml"), *d.glob("*.yml")]) if d.is_dir() else []


def read_yaml(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def parse_config(path: str | Path) -> ConnectorConfig:
    """Parse without env checks. Callers run the validator first."""
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
