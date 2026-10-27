#!/usr/bin/env python3
"""
store.py - sqlite layer for WebScan.

  scans    - one row per scan: what was scanned, when, and how it went
  results  - one row per host found in a scan
  seen     - when each host (by MAC, or by IP when the MAC is unknown) was
             first and last seen across all scans

New and gone hosts are worked out when a scan is read, by matching it against
an earlier scan of the same targets (see compare()). The counts for the scan
list are worked out once, when a scan finishes, and stored with it.

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id        INTEGER PRIMARY KEY,
  started   REAL NOT NULL,
  finished  REAL,
  targets   TEXT NOT NULL,             -- normalised, e.g. '192.168.100.0/24'
  addresses INTEGER NOT NULL,
  alive     INTEGER NOT NULL DEFAULT 0,
  new       INTEGER,                   -- vs the previous complete scan of the
  gone      INTEGER,                   -- same targets; NULL = nothing to compare
  status    TEXT NOT NULL,             -- running | done | stopped | error
  trigger   TEXT NOT NULL DEFAULT 'manual',
  error     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS scans_targets ON scans(targets, id);
CREATE TABLE IF NOT EXISTS results(
  scan_id   INTEGER NOT NULL,
  ip        TEXT NOT NULL,
  ipnum     INTEGER NOT NULL,
  mac       TEXT NOT NULL DEFAULT '',
  vendor    TEXT NOT NULL DEFAULT '',
  name      TEXT NOT NULL DEFAULT '',
  name_src  TEXT NOT NULL DEFAULT '',  -- dns | netbios
  workgroup TEXT NOT NULL DEFAULT '',
  via       TEXT NOT NULL DEFAULT '',  -- ping,arp,tcp,self
  rtt       REAL,                      -- ms, NULL = no ping answer
  ports     TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(scan_id, ipnum)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS seen(
  key        TEXT PRIMARY KEY,         -- MAC, or 'ip:' + address
  first_seen REAL NOT NULL,
  last_seen  REAL NOT NULL,
  last_ip    TEXT NOT NULL
) WITHOUT ROWID;
"""

COLUMNS = ("ip", "ipnum", "mac", "vendor", "name", "name_src", "workgroup", "via", "rtt", "ports")


def seen_key(row: dict) -> str:
    return row["mac"] or "ip:" + row["ip"]


def compare(cur: list[dict], prev: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    """Match the hosts of two scans. Returns ({ip: prev row} for the hosts in
    `cur` that were there before, and the rows of `prev` that are gone).

    A host is the same host if it has the same MAC and address; failing that
    the same MAC (it moved - DHCP gave it another address); failing that the
    same address (its MAC was not seen, or it is a new box on an old address).
    Matching on the address alone would call every DHCP shuffle one host gone
    and one new; matching on the MAC alone would lose hosts behind a router,
    where there is no MAC to see. Rows are used once each, so two addresses
    on one MAC (a printer's two interfaces) stay two hosts."""
    matched: dict[str, dict] = {}
    left = list(prev)
    for rule in (lambda a, b: a["mac"] and a["mac"] == b["mac"] and a["ip"] == b["ip"],
                 lambda a, b: a["mac"] and a["mac"] == b["mac"],
                 lambda a, b: a["ip"] == b["ip"]):
        for row in cur:
            if row["ip"] in matched:
                continue
            for k, old in enumerate(left):
                if rule(row, old):
                    matched[row["ip"]] = old
                    del left[k]
                    break
    return matched, left


class Store:
    def __init__(self, path: str):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        # A scan still 'running' at startup was cut off when we last stopped.
        self.db.execute("UPDATE scans SET status='error', error='interrupted - WebScan was stopped',"
                        " finished=COALESCE(finished, started) WHERE status='running'")
        self.db.commit()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    # -- generic -------------------------------------------------------
    def read(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute(sql, params).fetchall()

    def write(self, sql: str, params: tuple = ()):
        with self.lock:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur

    # -- scans ---------------------------------------------------------
    def new_scan(self, targets: str, addresses: int, trigger: str) -> int:
        cur = self.write("INSERT INTO scans(started,targets,addresses,status,trigger)"
                         " VALUES(?,?,?,'running',?)", (time.time(), targets, addresses, trigger))
        return int(cur.lastrowid)

    def scan(self, sid: int) -> dict | None:
        rows = self.read("SELECT * FROM scans WHERE id=?", (sid,))
        return dict(rows[0]) if rows else None

    def scans(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self.read("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    def latest(self) -> dict | None:
        rows = self.read("SELECT * FROM scans WHERE status IN ('done','stopped') ORDER BY id DESC LIMIT 1")
        return dict(rows[0]) if rows else None

    def previous(self, sid: int) -> dict | None:
        """The last complete scan of the same targets before `sid`. A stopped
        scan is missing hosts it never got to, so it is never the baseline."""
        rows = self.read("SELECT p.* FROM scans p JOIN scans s ON s.id=? WHERE p.targets=s.targets"
                         " AND p.id<s.id AND p.status='done' ORDER BY p.id DESC LIMIT 1", (sid,))
        return dict(rows[0]) if rows else None

    def comparable(self, sid: int) -> list[dict]:
        """Every complete scan of the same targets, newest first - the
        choices for comparing `sid` with."""
        return [dict(r) for r in self.read(
            "SELECT p.id, p.started, p.alive FROM scans p JOIN scans s ON s.id=?"
            " WHERE p.targets=s.targets AND p.id<>s.id AND p.status='done'"
            " ORDER BY p.id DESC LIMIT 200", (sid,))]

    def scanned_targets(self) -> list[str]:
        """Every distinct set of targets ever scanned."""
        return [r["targets"] for r in self.read("SELECT DISTINCT targets FROM scans")]

    def last_started(self, targets: str) -> float:
        rows = self.read("SELECT MAX(started) m FROM scans WHERE targets=?", (targets,))
        return float(rows[0]["m"] or 0.0)

    def finish_scan(self, sid: int, hosts: list[dict], status: str) -> None:
        now = time.time()
        rows = []
        for h in hosts:
            rows.append((sid, h["ip"], h["ipnum"], h["mac"], h["vendor"], h["name"], h["name_src"],
                         h["workgroup"], h["via"], h["rtt"], json.dumps(h["ports"])))
        with self.lock:
            self.db.executemany(
                "INSERT OR REPLACE INTO results(scan_id,ip,ipnum,mac,vendor,name,name_src,"
                "workgroup,via,rtt,ports) VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
            for h in hosts:
                self.db.execute(
                    "INSERT INTO seen(key,first_seen,last_seen,last_ip) VALUES(?,?,?,?)"
                    " ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,"
                    " last_ip=excluded.last_ip", (seen_key(h), now, now, h["ip"]))
            self.db.execute("UPDATE scans SET finished=?, status=?, alive=? WHERE id=?",
                            (now, status, len(hosts), sid))
            self.db.commit()
        self.recount(sid)

    def recount(self, sid: int) -> None:
        """Work out and store how many hosts in `sid` are new and gone."""
        new = gone = None
        prev = self.previous(sid)
        if prev:
            hosts = self.results(sid)
            matched, left = compare(hosts, self.results(prev["id"]))
            new, gone = len(hosts) - len(matched), len(left)
        self.write("UPDATE scans SET new=?, gone=? WHERE id=?", (new, gone, sid))

    def fail_scan(self, sid: int, error: str) -> None:
        self.write("UPDATE scans SET finished=?, status='error', error=? WHERE id=?",
                   (time.time(), error[:500], sid))

    def delete_scans(self, ids: list[int], recount: bool = True) -> int:
        """Delete scans. The scans that were compared with a deleted one are
        now compared with an older scan, so their new/gone counts are worked
        out again - unless `recount` is off (pruning only removes the oldest
        scans, which nothing later depends on for long)."""
        ids = sorted(set(ids))
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        gone = self.read("SELECT id, targets FROM scans WHERE id IN (%s)" % marks, tuple(ids))
        with self.lock:
            self.db.execute("DELETE FROM results WHERE scan_id IN (%s)" % marks, tuple(ids))
            self.db.execute("DELETE FROM scans WHERE id IN (%s)" % marks, tuple(ids))
            self.db.commit()
        if recount:
            span: dict[str, tuple[int, int]] = {}
            for r in gone:
                lo, hi = span.get(r["targets"], (r["id"], r["id"]))
                span[r["targets"]] = (min(lo, r["id"]), max(hi, r["id"]))
            for targets, (lo, hi) in span.items():
                # Any later scan up to and including the first complete one
                # after the last deleted scan may have had a deleted scan as
                # its baseline; from there on the baselines are untouched.
                for r in self.read("SELECT id, status FROM scans WHERE targets=? AND id>?"
                                   " AND status IN ('done','stopped') ORDER BY id", (targets, lo)):
                    self.recount(r["id"])
                    if r["status"] == "done" and r["id"] > hi:
                        break
        return len(gone)

    def prune(self, keep: int) -> int:
        """Drop all but the newest `keep` scans."""
        rows = self.read("SELECT id FROM scans WHERE status<>'running' ORDER BY id DESC LIMIT -1 OFFSET ?",
                         (keep,))
        return self.delete_scans([r["id"] for r in rows], recount=False)

    # -- results -------------------------------------------------------
    def results(self, sid: int) -> list[dict]:
        out = []
        for r in self.read("SELECT %s FROM results WHERE scan_id=? ORDER BY ipnum" % ",".join(COLUMNS),
                           (sid,)):
            d = dict(r)
            d["ports"] = json.loads(d["ports"] or "[]")
            out.append(d)
        return out

    def first_seen(self, keys: list[str]) -> dict[str, float]:
        out: dict[str, float] = {}
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            for r in self.read("SELECT key, first_seen FROM seen WHERE key IN (%s)"
                               % ",".join("?" * len(chunk)), tuple(chunk)):
                out[r["key"]] = r["first_seen"]
        return out

    def stats(self) -> dict:
        r = self.read("SELECT (SELECT COUNT(*) FROM scans) s, (SELECT COUNT(*) FROM results) r,"
                      " (SELECT COUNT(*) FROM seen) h")[0]
        return {"scans": r["s"], "results": r["r"], "known_hosts": r["h"]}
