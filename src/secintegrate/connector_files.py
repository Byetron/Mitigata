"""Creating and removing connector files. Shared by the web UI and the CLI."""
from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from .config.loader import config_files, find_connector_file, parse_config
from .config.schema import ID_RE
from .storage.db import Database

logger = logging.getLogger(__name__)

TRASH_DIR = ".trash"
TEMPLATE_PATH = Path(__file__).parent / "config" / "template.yaml"


def template_text() -> str:
    """The commented boilerplate shown on the New connector page and printed by `hermes template`."""
    return TEMPLATE_PATH.read_text(encoding="utf-8")


cr, nl = chr(13), chr(10)


def write_connector(config_dir: Path, connector: str, text: str) -> Path:
    """Save validated YAML as <connector>.yaml. The id was checked by the validator; check it again here."""
    if not ID_RE.match(connector):
        raise ValueError("invalid connector id")
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / f"{connector}.yaml"
    clean = text.replace(cr + nl, nl).replace(cr, nl)  # a browser sends CRLF; Windows would double it on write
    with target.open("w", encoding="utf-8", newline="") as handle:
        handle.write(clean)
    return target


@dataclass(frozen=True)
class Removal:
    config: Path  # where the config now lives, in the trash
    records: int  # fetched records that were deleted with it


def _sources_in_use(config_dir: Path) -> set[str]:
    used: set[str] = set()
    for f in config_files(config_dir):
        try:
            used.add(parse_config(f).source)
        except (ValidationError, yaml.YAMLError):
            continue
    return used


def remove_connector(config_dir: Path, db: Database, connector: str) -> Removal | None:
    """Move the config to `.trash/` (so it can be restored) and delete its health history AND the records it fetched.

    Returns None when no such connector exists.
    """
    if not ID_RE.match(connector):
        return None
    file = find_connector_file(config_dir, connector)
    if file is None or file.parent.resolve() != config_dir.resolve():
        return None
    try:
        source: str | None = parse_config(file).source
    except (ValidationError, yaml.YAMLError):
        source = None  # an unreadable config: only rows tagged with this connector can be matched
    trash = config_dir / TRASH_DIR
    trash.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = trash / f"{file.stem}-{stamp}.yaml"
    shutil.move(str(file), destination)
    shared = source is not None and source in _sources_in_use(config_dir)  # another connector still uses the label
    records = db.delete_connector_data(connector, source, shared)
    records += db.delete_orphan_records(_sources_in_use(config_dir))  # rows left under an older source label
    db.delete_connector_state(connector)
    logger.info("removed connector %s and %d record(s) (config kept in %s)", connector, records, destination)
    return Removal(destination, records)
