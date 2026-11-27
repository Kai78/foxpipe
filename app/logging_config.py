"""Friendly rotating logfile configuration and log viewer utilities."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import AppConfig

LOGGER_NAME = "gitlab_pipeline_runner"


def configure_logging(config: AppConfig) -> logging.Logger:
    """Configure friendly human-readable console and rotating file logging."""
    logger = logging.getLogger(LOGGER_NAME)
    level = getattr(logging, config.logging.level.upper(), logging.INFO)
    logger.setLevel(level)
    logger.propagate = False

    # Reset handlers cleanly on re-initialization
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        existing.close()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log_path = config.resolve_path(config.logging.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=config.logging.max_bytes,
        backupCount=config.logging.backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    logger.info("Pipeline runner logger initialized (logfile=%s, level=%s).", log_path, config.logging.level)
    return logger


def get_logger() -> logging.Logger:
    """Retrieve the shared application logger."""
    return logging.getLogger(LOGGER_NAME)


def read_recent_log_lines(
    log_file: Path,
    limit: int = 200,
    level_filter: str = "ALL",
) -> list[dict[str, str]]:
    """Read and parse recent lines from the configured logfile for dashboard display."""
    if not log_file.exists():
        return []

    try:
        raw_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    parsed: list[dict[str, str]] = []
    normalized_filter = level_filter.strip().upper()

    for line in raw_lines[-max(limit * 2, 400):]:
        parts = [part.strip() for part in line.split("|", 2)]
        if len(parts) == 3:
            timestamp, level, message = parts
        else:
            timestamp, level, message = "", "INFO", line

        if normalized_filter not in ("", "ALL") and level.upper() != normalized_filter:
            continue

        parsed.append(
            {
                "timestamp": timestamp,
                "level": level.upper(),
                "message": message,
            }
        )

    return parsed[-limit:][::-1]
