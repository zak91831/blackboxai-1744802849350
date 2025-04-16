"""
CacheXSSDetector - A comprehensive Cache-based XSS vulnerability detection tool.

This package provides tools and utilities for detecting Cache-based XSS vulnerabilities
in web applications through various testing methodologies and analysis techniques.
"""

__version__ = "0.1.0"
__author__ = "Sudani.Zak"
__email__ = "sudani.zak@gmail.com"

from . import cli
from . import core
from . import request
from . import verification
from . import utils

__all__ = ["cli", "core", "request", "verification", "utils"]
