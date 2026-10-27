#!/usr/bin/env python3
"""
suggest.py - which subnet does an address belong to?

Type 10.0.1.17 into the scan field and the right thing to scan is usually not
that one address, and not the /24 around it either - here it is 10.0.0.0/22.
The answer is looked up, best source first:

  netbox   - the prefixes documented in NetBox (optional, read-only API call)
  local    - networks this machine has an address on, with their real mask
  history  - subnets that have been scanned before
  guess    - the /24 around the address, only when nothing else knows

NetBox is asked at most every five minutes. If it cannot be reached, or no
token is configured, the other sources still work.

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

import scanner

CACHE_SECONDS = 300
RETRY_SECONDS = 60

Net = ipaddress.IPv4Network


def _usable(net: Net) -> int:
    return net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses


def _label(description: str) -> str:
    """The first sentence of a NetBox description: 'VLAN 2 Wireless.
    Scanned 2026-10-08: ...' becomes 'VLAN 2 Wireless'."""
    first = re.split(r"\.\s+(?=[A-Z])", description.strip() + " ", maxsplit=1)[0]
    first = first.strip().rstrip(".")
    return first[:70] + ("..." if len(first) > 70 else "")


class Suggester:
    def __init__(self):
        self._lock = threading.Lock()
        self._cache: tuple[float, str, list[tuple[Net, str]]] = (0.0, "", [])
        self._warned = ""

    # -- NetBox --------------------------------------------------------
    def netbox_prefixes(self, cfg: dict) -> list[tuple[Net, str]]:
        url = (cfg.get("netbox_url") or "").rstrip("/")
        if not url:
            return []
        with self._lock:
            until, cached_url, prefixes = self._cache
            if cached_url == url and time.time() < until:
                return prefixes
        try:
            prefixes = self._fetch(url, os.path.expanduser(cfg.get("netbox_token_file") or ""))
            until = time.time() + CACHE_SECONDS
            self._warned = ""
        except (OSError, ValueError, urllib.error.URLError) as exc:
            msg = str(exc)
            if msg != self._warned:
                print("[webscan] NetBox prefixes unavailable (%s) - suggesting without them" % msg,
                      flush=True)
                self._warned = msg
            prefixes, until = [], time.time() + RETRY_SECONDS
        with self._lock:
            self._cache = (until, url, prefixes)
        return prefixes

    @staticmethod
    def _fetch(url: str, token_file: str) -> list[tuple[Net, str]]:
        with open(token_file, "r", encoding="utf-8") as fh:
            token = re.sub(r"^(Bearer|Token)\s+", "", fh.read().strip()).strip()
        # NetBox v2 tokens (nbt_<key>.<secret>) go with Bearer, legacy ones with Token.
        scheme = "Bearer" if "." in token else "Token"
        out: list[tuple[Net, str]] = []
        nxt = url + "/api/ipam/prefixes/?family=4&limit=1000"
        while nxt:
            req = urllib.request.Request(nxt, headers={"Authorization": "%s %s" % (scheme, token),
                                                       "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                page = json.loads(resp.read())
            for p in page.get("results", []):
                try:
                    net = ipaddress.IPv4Network(p["prefix"], strict=False)
                except (KeyError, ValueError):
                    continue
                vlan = (p.get("vlan") or {}).get("name", "") if isinstance(p.get("vlan"), dict) else ""
                out.append((net, _label(p.get("description") or "") or vlan))
            nxt = page.get("next")
        return out

    # -- all sources ---------------------------------------------------
    def suggest(self, ip: str, cfg: dict, scanned: list[str]) -> list[dict]:
        addr = ipaddress.IPv4Address(ip)
        found: list[dict] = []
        seen: set[Net] = set()

        def add(net: Net, source: str, label: str) -> None:
            if net in seen or addr not in net or net.prefixlen == 32:
                return
            seen.add(net)
            found.append({"net": str(net), "source": source, "label": label,
                          "addresses": _usable(net), "too_big": _usable(net) > cfg["max_hosts"]})

        # Within a source the most specific prefix comes first: a /24 carved
        # out of a documented /16 is the better answer.
        for net, label in sorted(self.netbox_prefixes(cfg), key=lambda x: -x[0].prefixlen):
            add(net, "netbox", label)
        for i in scanner.local_interfaces():
            add(i["net"], "local", "this server is on it (%s)" % i["dev"])
        nets = []
        for text in scanned:
            for tok in text.split():
                if "/" in tok:
                    try:
                        nets.append(ipaddress.IPv4Network(tok, strict=False))
                    except ValueError:
                        pass
        for net in sorted(set(nets), key=lambda n: -n.prefixlen):
            add(net, "history", "scanned before")
        if not found:
            add(ipaddress.IPv4Network("%s/24" % ip, strict=False), "guess", "guess - nothing knows this address")
        return found
