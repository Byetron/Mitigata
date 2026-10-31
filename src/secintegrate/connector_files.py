"""Creating and removing connector files. Shared by the web UI and the CLI."""
from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .config.loader import find_connector_file
from .config.schema import ID_RE
from .storage.db import Database

logger = logging.getLogger(__name__)

TRASH_DIR = ".trash"
TEMPLATE_PATH = Path(__file__).parent / "config" / "template.yaml"


def template_text() -> str:
    """The commented boilerplate shown on the New connector page and printed by `hermes template`."""
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def write_connector(config_dir: Path, connector: str, text: str) -> Path:
    """Save validated YAML as <connector>.yaml. The id was checked by the validator; check it again here."""
    if not ID_RE.match(connector):
        raise ValueError("invalid connector id")
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / f"{connector}.yaml"
    target.write_text(text, encoding="utf-8")
    return target


def remove_connector(config_dir: Path, db: Database, connector: str) -> Path | None:
    """Move the config to `.trash/` (so it can be restored) and forget its health and history.

    Fetched records stay. Returns the trash path, or None when no such connector exists.
    """
    if not ID_RE.match(connector):
        return None
    file = find_connector_file(config_dir, connector)
    if file is None or file.parent.resolve() != config_dir.resolve():
        return None
    trash = config_dir / TRASH_DIR
    trash.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = trash / f"{file.stem}-{stamp}.yaml"
    shutil.move(str(file), destination)
    db.delete_connector_state(connector)
    logger.info("removed connector %s (config kept in %s)", connector, destination)
    return destination
