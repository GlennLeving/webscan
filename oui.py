#!/usr/bin/env python3
"""
oui.py - MAC address to manufacturer, from the IEEE registry files.

Ubuntu and Debian ship the registry in /usr/share/ieee-data (package
ieee-data). Four files matter:

  oui.csv    - MA-L, 24-bit prefixes, the classic OUI
  mam.csv    - MA-M, 28-bit prefixes
  oui36.csv  - MA-S, 36-bit prefixes
  iab.csv    - the older IAB blocks, also 36-bit

The longer prefixes are blocks carved out of a larger one, so a lookup tries
the longest first. The files are read once, on first use.

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import csv
import os
import threading

FILES = ("oui36.csv", "iab.csv", "mam.csv", "oui.csv")

_lock = threading.Lock()
_table: dict[str, str] | None = None
_dir = "/usr/share/ieee-data"


def configure(directory: str) -> None:
    """Point at another registry directory. The next lookup reloads."""
    global _dir, _table
    with _lock:
        if directory != _dir:
            _dir, _table = directory, None


def _load() -> dict[str, str]:
    table: dict[str, str] = {}
    for name in FILES:
        path = os.path.join(_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
                for row in csv.reader(fh):
                    if len(row) < 3 or row[0] == "Registry":
                        continue
                    prefix = row[1].strip().upper()
                    org = " ".join(row[2].split())
                    if prefix and org:
                        table.setdefault(prefix, org)
        except OSError:
            continue
    return table


def size() -> int:
    return len(_get())


def _get() -> dict[str, str]:
    global _table
    with _lock:
        if _table is None:
            _table = _load()
        return _table


def lookup(mac: str) -> str:
    """Manufacturer for a MAC address, '' when unknown. A locally
    administered address (phones and laptops randomise their MAC per network)
    has no manufacturer, and says so."""
    hexd = "".join(c for c in mac.upper() if c in "0123456789ABCDEF")
    if len(hexd) != 12:
        return ""
    table = _get()
    for n in (9, 7, 6):
        org = table.get(hexd[:n])
        if org:
            if org == "IEEE Registration Authority":
                # A 24-bit block the IEEE hands out in small pieces, and this
                # piece is newer than the local copy of the registry.
                return "(small IEEE block, not in local registry)"
            return org
    if int(hexd[1], 16) & 0x2:
        return "(randomized MAC)"
    return ""
