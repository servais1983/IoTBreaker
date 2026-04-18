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
    name: str = "iotbreaker"
) -> logging.Logger:
    """
    Configure the root logger for IoTBreaker.

    Parameters
    ----------
    level : int
        Logging level (e.g. logging.DEBUG, logging.INFO).
    log_file : str, optional
        Path to a file for persistent log output.
    name : str
        Root logger name.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    global _LOGGER_INITIALIZED

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if _LOGGER_INITIALIZED:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
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
