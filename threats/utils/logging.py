"""Structured logging setup."""

import logging
import logging.handlers
import os
from pathlib import Path


def setup_logging(
    level: str = "INFO",
    log_file: str | Path = "logs/threats.log",
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> None:
    level_val = getattr(logging, level.upper(), logging.INFO)
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)-30s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level_val)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Silence noisy third-party libraries
    for lib in ("urllib3", "chardet", "feedparser"):
        logging.getLogger(lib).setLevel(logging.WARNING)
