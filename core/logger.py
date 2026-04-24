#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Logging System

Provides structured, leveled logging with optional file output
and clean console formatting.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


_LOGGER_INITIALIZED = False
_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    level: int = logging.WARNING,
    log_file: str = None,
    name: str = "iotbreaker",
    output_dir: str = None,
    session_id: str = None,
) -> logging.Logger:
    """
    Configure the root logger for IoTBreaker.

    Parameters
    ----------
    level : int
        Logging level (e.g. logging.DEBUG, logging.INFO).
    log_file : str, optional
        Explicit path to a log file. Takes precedence over output_dir/session_id.
    name : str
        Root logger name.
    output_dir : str, optional
        S10: Directory to write the mandatory audit log file. A timestamped
        log is always written here regardless of console verbosity level.
    session_id : str, optional
        S10: Session identifier used to name the audit log file.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    global _LOGGER_INITIALIZED

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # capture everything; handlers filter by level

    if _LOGGER_INITIALIZED:
        return logger

    # Console handler — respects the requested verbosity level
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
    logger.addHandler(console_handler)

    # S10: Determine audit log path
    resolved_log_file = log_file
    if not resolved_log_file and output_dir:
        sid = session_id or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        resolved_log_file = str(Path(output_dir) / f"iotbreaker_{sid}.log")

    # S10: Always write a full DEBUG-level audit log to disk
    if resolved_log_file:
        Path(resolved_log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(resolved_log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
        logger.addHandler(file_handler)

    _LOGGER_INITIALIZED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Retrieve a child logger under the iotbreaker namespace.

    Parameters
    ----------
    name : str
        Module name (typically __name__).

    Returns
    -------
    logging.Logger
    """
    if "." in name:
        # Strip leading package path for cleaner names
        name = name.split(".")[-1]
    return logging.getLogger(f"iotbreaker.{name}")
