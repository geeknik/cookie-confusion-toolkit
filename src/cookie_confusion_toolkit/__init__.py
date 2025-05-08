"""
Cookie Confusion Toolkit (CCT)

A security research toolkit for identifying, testing, and validating cookie parsing
inconsistencies across browser and server implementations.

This package contains tools to assist security researchers and developers in
understanding and mitigating cookie-related security vulnerabilities.

Copyright (C) 2025 <Author>
License: GPLv3 with Ethical Use Clause
"""

__version__ = "0.1.0"
__author__ = "Geeknik"
__license__ = "GPLv3 with Ethical Use Clause"

from .bypassgen import BypassGen
from .clientfork import ClientFork
from .cookiebomb import CookieBomb
from .serverdrift import ServerDrift

__all__ = ["CookieBomb", "ClientFork", "ServerDrift", "BypassGen"]
