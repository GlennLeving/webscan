#!/usr/bin/env python3
"""
engine.py - runs scans for WebScan, one at a time, and on a schedule.

A scan runs in a background thread; the web UI follows it through status().
Results are written in one go when the scan ends, so a scan that is still
running never shows up half-finished as the 'latest' one.

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import threading
import time
import traceback

import scanner
from store import Store

DEFAULT_CONFIG = {
    "default_targets": "192.168.100.0/24",
    "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 631,
              1433, 3306, 3389, 5900, 5985, 8080, 8443, 9100],
    "discovery_ports": [22, 80, 443, 445, 3389],
    "dns_servers": ["192.168.65.170", "192.168.65.172"],
    "resolve_names": True,
    "netbios": True,
    "http_titles": True,
    "ping_timeout": 1.0,
    "ping_rounds": 2,
    "arp_wait_seconds": 10.0,
    "connect_timeout": 0.8,
    "dns_timeout": 1.5,
    "detail_timeout": 3.0,
    "threads": 128,
    "max_hosts": 1024,
    "schedule_minutes": 0,
    "keep_scans": 200,
    "oui_dir": "/usr/share/ieee-data",
    "netbox_url": "http://127.0.0.1:8001",
    "netbox_token_file": "~/.netbox-token",
}

PHASES = ("ping", "arp", "discovery", "ports", "names", "netbios", "details")


class Engine:
    def __init__(self, store: Store, config: dict):
        self.store = store
        self.config = config
        self.lock = threading.Lock()
        self.job: dict | None = None
        self.last_error = ""
        self._stop = threading.Event()
        self._quit = threading.Event()
        self._sched = threading.Thread(target=self._schedule_loop, name="schedule", daemon=True)
        self._sched.start()

    # -- control -------------------------------------------------------
    def start(self, text: str, trigger: str = "manual") -> int:
        cfg = dict(self.config)
        addrs, norm = scanner.parse_targets(text, int(cfg["max_hosts"]))
        with self.lock:
            if self.job is not None:
                raise RuntimeError("a scan is already running")
            sid = self.store.new_scan(norm, len(addrs), trigger)
            self.job = {"id": sid, "targets": norm, "addresses": len(addrs), "trigger": trigger,
                        "started": time.time(), "phase": "starting", "done": 0, "total": 0,
                        "stopping": False}
            self._stop.clear()
        threading.Thread(target=self._run, args=(sid, addrs, cfg), name="scan-%d" % sid,
                         daemon=True).start()
        return sid

    def stop(self) -> bool:
        with self.lock:
            if self.job is None:
                return False
            self.job["stopping"] = True
        self._stop.set()
        return True

    def status(self) -> dict | None:
        with self.lock:
            return dict(self.job) if self.job else None

    def shutdown(self) -> None:
        self._quit.set()
        self._stop.set()

    # -- the scan ------------------------------------------------------
    def _progress(self, phase: str, done: int, total: int) -> None:
        with self.lock:
            if self.job is not None:
                self.job.update(phase=phase, done=done, total=total)

    def _run(self, sid: int, addrs: list[str], cfg: dict) -> None:
        t0 = time.monotonic()
        try:
            hosts = scanner.scan(addrs, cfg, self._progress, self._stop.is_set)
            for h in hosts:
                h["ipnum"] = scanner.ipnum(h["ip"])
            status = "stopped" if self._stop.is_set() else "done"
            self.store.finish_scan(sid, hosts, status)
            print("[webscan] scan #%d of %s: %d hosts in %.1fs (%s)"
                  % (sid, self.job["targets"], len(hosts), time.monotonic() - t0, status), flush=True)
        except Exception as exc:
            traceback.print_exc()
            self.store.fail_scan(sid, "%s: %s" % (type(exc).__name__, exc))
        finally:
            with self.lock:
                self.job = None
        try:
            self.store.prune(int(cfg["keep_scans"]))
        except Exception as exc:          # pruning is housekeeping - never fatal
            print("[webscan] pruning old scans failed: %s" % exc, flush=True)

    # -- schedule ------------------------------------------------------
    def _schedule_loop(self) -> None:
        while not self._quit.wait(20):
            cfg = self.config
            minutes = float(cfg.get("schedule_minutes") or 0)
            if minutes <= 0 or self.status() is not None:
                continue
            try:
                _addrs, norm = scanner.parse_targets(cfg["default_targets"], int(cfg["max_hosts"]))
                if time.time() - self.store.last_started(norm) >= minutes * 60:
                    self.start(cfg["default_targets"], "schedule")
                self.last_error = ""
            except (ValueError, RuntimeError) as exc:
                if str(exc) != self.last_error:
                    print("[webscan] scheduled scan not started: %s" % exc, flush=True)
                self.last_error = str(exc)
