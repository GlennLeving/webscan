#!/usr/bin/env python3
"""
WebScan - network scanner with a web UI (Advanced IP Scanner, in the browser).

Scans one or more subnets and shows, for every host found, its address,
name, MAC, manufacturer, whether it answers ping, and which ports are open
and what is behind them. Every scan is kept, so the next one can show which
hosts are new and which are gone. No dependencies - only the Python 3
standard library. Normally no root either (see the README).

Start:  python3 webscan.py                 (web UI on http://127.0.0.1:8422)
        python3 webscan.py --host 0.0.0.0

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import argparse
import csv
import getpass
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import engine as engine_mod           # noqa: E402
import oui                            # noqa: E402
import scanner                        # noqa: E402
import suggest                        # noqa: E402
from store import Store, compare, seen_key   # noqa: E402

STATIC_DIR = os.path.join(BASE_DIR, "static")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DB_PATH = os.path.join(BASE_DIR, "webscan.db")
AUTH_PATH = os.path.join(BASE_DIR, "auth.json")

PBKDF2_ITERATIONS = 240_000
SESSION_TTL = 12 * 3600
MAX_FAILED = 5
LOCKOUT_SECONDS = 300

# Bounds for the settings, so the UI cannot set anything unreasonable.
LIMITS = {
    "ping_timeout": (0.2, 10.0, float),
    "ping_rounds": (1, 5, int),
    "arp_wait_seconds": (0.0, 30.0, float),
    "connect_timeout": (0.1, 10.0, float),
    "dns_timeout": (0.2, 10.0, float),
    "detail_timeout": (0.5, 15.0, float),
    "threads": (1, 512, int),
    "max_hosts": (1, 4096, int),
    "schedule_minutes": (0, 10080, int),
    "keep_scans": (5, 10000, int),
}
FLAGS = ("resolve_names", "netbios", "http_titles")

store: Store
eng: engine_mod.Engine
suggester = suggest.Suggester()
_cfg_lock = threading.Lock()


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
def load_config() -> dict:
    cfg = dict(engine_mod.DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    except FileNotFoundError:
        save_config(cfg)
    except (json.JSONDecodeError, OSError) as exc:
        print("[webscan] could not read config.json (%s) - using defaults" % exc)
    try:
        return validate_config(cfg)
    except ValueError as exc:
        print("[webscan] config.json: %s - using defaults" % exc)
        return dict(engine_mod.DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, CONFIG_PATH)


def _port_list(raw, key: str) -> list[int]:
    if isinstance(raw, str):
        raw = [p for p in raw.replace(",", " ").split() if p]
    if not isinstance(raw, list):
        raise ValueError("%s must be a list of port numbers" % key)
    out = []
    for p in raw:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise ValueError("%s: '%s' is not a port number" % (key, p)) from None
        if not 1 <= n <= 65535:
            raise ValueError("%s: %d is not a port number" % (key, n))
        out.append(n)
    if len(out) > 1000:
        raise ValueError("%s: at most 1000 ports" % key)
    return sorted(set(out))


def validate_config(raw: dict) -> dict:
    """Clean settings, or ValueError saying what is wrong with them."""
    out = dict(engine_mod.DEFAULT_CONFIG)
    for key, (lo, hi, cast) in LIMITS.items():
        try:
            val = cast(raw.get(key, out[key]))
        except (TypeError, ValueError):
            val = out[key]
        out[key] = max(lo, min(hi, val))
    for key in FLAGS:
        out[key] = bool(raw.get(key, out[key]))
    out["ports"] = _port_list(raw.get("ports", out["ports"]), "ports")
    out["discovery_ports"] = _port_list(raw.get("discovery_ports", out["discovery_ports"]),
                                        "discovery_ports")
    servers = raw.get("dns_servers", out["dns_servers"])
    if isinstance(servers, str):
        servers = servers.replace(",", " ").split()
    try:
        out["dns_servers"] = [str(ipaddress.IPv4Address(str(s).strip())) for s in servers][:4]
    except ValueError:
        raise ValueError("dns_servers must be IPv4 addresses") from None
    targets = str(raw.get("default_targets", out["default_targets"])).strip()
    scanner.parse_targets(targets, out["max_hosts"])        # raises if unusable
    out["default_targets"] = targets
    out["oui_dir"] = str(raw.get("oui_dir", out["oui_dir"])).strip() or out["oui_dir"]
    url = str(raw.get("netbox_url", out["netbox_url"]) or "").strip().rstrip("/")
    if url and not re.match(r"^https?://[^\s/]+(/\S*)?$", url):
        raise ValueError("netbox_url must be an http:// or https:// address, or empty")
    out["netbox_url"] = url
    out["netbox_token_file"] = str(raw.get("netbox_token_file", out["netbox_token_file"]) or "").strip()
    return out


def apply_config(new: dict) -> dict:
    # Merge onto the running config so a client that only sends some of the
    # fields does not silently reset the rest to their defaults.
    cfg = validate_config({**eng.config, **(new or {})})
    with _cfg_lock:
        save_config(cfg)
        eng.config = cfg
    oui.configure(cfg["oui_dir"])
    return cfg


# --------------------------------------------------------------------------
# Password and sessions
# --------------------------------------------------------------------------
_auth_lock = threading.Lock()
_sessions: dict[str, float] = {}
_failed: dict[str, tuple[int, float]] = {}


def hash_password(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": PBKDF2_ITERATIONS}


def set_password(password: str) -> None:
    if len(password) < 4:
        raise ValueError("the password must be at least 4 characters")
    tmp = AUTH_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(hash_password(password), fh, indent=2)
        fh.write("\n")
    os.replace(tmp, AUTH_PATH)
    os.chmod(AUTH_PATH, 0o600)
    with _auth_lock:
        _sessions.clear()             # changing the password logs everyone out


def has_password() -> bool:
    return os.path.exists(AUTH_PATH)


def check_password(password: str) -> bool:
    try:
        with open(AUTH_PATH, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(rec["salt"]), int(rec["iterations"]))
        return hmac.compare_digest(digest.hex(), rec["hash"])
    except Exception:
        return False


def new_session() -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _auth_lock:
        for tok, exp in list(_sessions.items()):
            if exp < now:
                del _sessions[tok]
        _sessions[token] = now + SESSION_TTL
    return token


def valid_session(token: str | None) -> bool:
    if not token:
        return False
    with _auth_lock:
        exp = _sessions.get(token)
        if exp is None:
            return False
        if exp < time.time():
            del _sessions[token]
            return False
    return True


def drop_session(token: str | None) -> None:
    if token:
        with _auth_lock:
            _sessions.pop(token, None)


def lockout_left(ip: str) -> int:
    with _auth_lock:
        _count, until = _failed.get(ip, (0, 0.0))
    return max(0, int(until - time.time()))


def note_login(ip: str, ok: bool) -> None:
    with _auth_lock:
        if ok:
            _failed.pop(ip, None)
            return
        count, until = _failed.get(ip, (0, 0.0))
        count += 1
        if count >= MAX_FAILED:
            _failed[ip] = (0, time.time() + LOCKOUT_SECONDS)
            print("[webscan] too many failed logins from %s - blocked for %ds"
                  % (ip, LOCKOUT_SECONDS))
        else:
            _failed[ip] = (count, until)


# --------------------------------------------------------------------------
# Scan results, with new and gone hosts
# --------------------------------------------------------------------------
def scan_view(sid: int, vs: int = 0) -> dict | None:
    """One scan's hosts, each marked new or not against a baseline scan, plus
    the hosts of the baseline that are gone. The baseline is `vs` when given
    (it must be a scan of the same targets), else the previous complete one."""
    scan = store.scan(sid)
    if scan is None:
        return None
    hosts = store.results(sid)
    base = store.scan(vs) if vs else store.previous(sid)
    if base and (base["targets"] != scan["targets"] or base["id"] == sid):
        base = None
    gone: list[dict] = []
    if base:
        matched, gone = compare(hosts, store.results(base["id"]))
        for h in hosts:
            old = matched.get(h["ip"])
            h["change"] = "" if old else "new"
            if old and old["ip"] != h["ip"]:
                h["moved_from"] = old["ip"]
        for g in gone:
            g["change"] = "gone"
    first = store.first_seen([seen_key(h) for h in hosts + gone])
    for h in hosts + gone:
        h["first_seen"] = first.get(seen_key(h))
    return {"scan": scan, "base": base, "hosts": hosts, "gone": gone,
            "comparable": store.comparable(sid)}


CSV_HEAD = ["status", "ip", "name", "mac", "vendor", "ping_ms", "found_by",
            "open_ports", "services", "workgroup", "first_seen"]


def csv_rows(view: dict) -> list[list[str]]:
    rows = []
    for h in view["hosts"] + view["gone"]:
        first = h.get("first_seen")
        rows.append([
            h.get("change", "") or "", h["ip"], h["name"], h["mac"], h["vendor"],
            "" if h["rtt"] is None else "%.2f" % h["rtt"], h["via"],
            " ".join(str(p["port"]) for p in h["ports"]),
            "; ".join("%d/%s%s" % (p["port"], p["service"], (" " + p["info"]) if p["info"] else "")
                      for p in h["ports"]),
            h["workgroup"],
            time.strftime("%Y-%m-%d %H:%M", time.localtime(first)) if first else "",
        ])
    return rows


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "webscan"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):        # no access log on stdout
        pass

    # -- helpers -------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, val in (extra or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, obj, code: int = 200, extra: dict | None = None):
        self._send(code, json.dumps(obj).encode("utf-8"),
                   "application/json; charset=utf-8", extra)

    def fail(self, code: int, msg: str):
        self.json({"error": msg}, code)

    def body_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if n <= 0 or n > 1 << 20:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            return SimpleCookie(raw).get("webscan_session", None).value
        except Exception:
            return None

    def authed(self) -> bool:
        # With no password set everything is open - one can be set in the UI.
        return not has_password() or valid_session(self.token())

    def require_auth(self) -> bool:
        if self.authed():
            return True
        self.fail(401, "login required")
        return False

    def client_ip(self) -> str:
        peer = self.client_address[0] if self.client_address else "?"
        # Behind the local nginx every request arrives from loopback, so the
        # login lockout would treat all users as one and a few wrong passwords
        # would block everyone. The real client is the last address nginx
        # appended to X-Forwarded-For. The header is only trusted from
        # loopback, so a client connecting directly cannot forge it.
        if peer in ("127.0.0.1", "::1"):
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd.strip():
                return fwd.split(",")[-1].strip()
        return peer

    # -- routes --------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if path == "/":
                return self.serve_static("index.html")
            if path.startswith("/static/"):
                return self.serve_static(path[len("/static/"):])
            if path == "/api/state":
                return self.json(self.state())
            if path in ("/api/status", "/api/health"):
                return self.json({"ok": True, "scanning": eng.status() is not None})
            if path == "/api/scans":
                lim = max(1, min(1000, _int(query.get("limit", ["100"])[0]) or 100))
                return self.json({"scans": store.scans(lim)})
            if path == "/api/scan":
                return self.get_scan(query)
            if path == "/api/suggest":
                return self.suggest(query)
            if path == "/api/session":
                return self.json({"authed": self.authed(),
                                  "protected": has_password(),
                                  "lockout": lockout_left(self.client_ip())})
            if path == "/api/config":
                with _cfg_lock:
                    return self.json(dict(eng.config))
            if path == "/api/export.csv":
                return self.export_csv(query)
            return self.fail(404, "unknown path")
        except BrokenPipeError:
            pass
        except Exception as exc:
            self.fail(500, str(exc))

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.body_json()
        try:
            if path == "/api/login":
                return self.login(data)
            if path == "/api/logout":
                drop_session(self.token())
                return self.json({"ok": True}, extra={
                    "Set-Cookie": "webscan_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            if path == "/api/set-password":
                return self.change_password(data)

            if not self.require_auth():
                return
            if path == "/api/scan/start":
                text = str(data.get("targets") or eng.config["default_targets"])
                try:
                    sid = eng.start(text)
                except ValueError as exc:
                    return self.fail(400, str(exc))
                except RuntimeError as exc:
                    return self.fail(409, str(exc))
                return self.json({"ok": True, "id": sid})
            if path == "/api/scan/stop":
                return self.json({"ok": eng.stop()})
            if path == "/api/scan/delete":
                raw = data.get("ids")
                ids = [_int(i) for i in raw] if isinstance(raw, list) else [_int(data.get("id"))]
                ids = [i for i in ids if i > 0]
                job = eng.status()
                if not ids or (job and job["id"] in ids):
                    return self.fail(400, "nothing to delete, or the scan is still running")
                return self.json({"ok": True, "deleted": store.delete_scans(ids)})
            if path == "/api/config":
                try:
                    cfg = apply_config(data)
                except ValueError as exc:
                    return self.fail(400, str(exc))
                return self.json({"ok": True, "config": cfg})
            return self.fail(404, "unknown path")
        except BrokenPipeError:
            pass
        except Exception as exc:
            self.fail(500, str(exc))

    # -- actions -------------------------------------------------------
    def state(self) -> dict:
        with _cfg_lock:
            cfg = dict(eng.config)
        return {
            "now": time.time(),
            "job": eng.status(),
            "scans": store.scans(100),
            "config": cfg,
            "authed": self.authed(),
            "protected": has_password(),
            "mode": PROBE_MODE,
            "db": store.stats(),
        }

    def get_scan(self, query: dict):
        sid = _int(query.get("id", [""])[0])
        if not sid:
            latest = store.latest()
            if latest is None:
                return self.json({"scan": None, "hosts": [], "gone": [], "base": None,
                                  "comparable": []})
            sid = latest["id"]
        view = scan_view(sid, _int(query.get("vs", [""])[0]))
        if view is None:
            return self.fail(404, "no such scan")
        return self.json(view)

    def suggest(self, query: dict):
        ip = query.get("ip", [""])[0].strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return self.json({"ip": ip, "suggestions": []})
        with _cfg_lock:
            cfg = dict(eng.config)
        return self.json({"ip": ip, "suggestions": suggester.suggest(ip, cfg, store.scanned_targets())})

    def export_csv(self, query: dict):
        sid = _int(query.get("id", query.get("scan", [""]))[0])
        if not sid:
            latest = store.latest()
            sid = latest["id"] if latest else 0
        view = scan_view(sid, _int(query.get("vs", [""])[0])) if sid else None
        if view is None:
            return self.fail(404, "no such scan")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_HEAD)
        w.writerows(csv_rows(view))
        stamp = time.strftime("%Y%m%d-%H%M", time.localtime(view["scan"]["started"]))
        # A BOM so Excel opens the file as UTF-8 and the names come out right.
        self._send(200, ("﻿" + buf.getvalue()).encode("utf-8"), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="webscan-%d-%s.csv"' % (sid, stamp)})

    def login(self, data: dict):
        ip = self.client_ip()
        left = lockout_left(ip)
        if left:
            return self.fail(429, "too many attempts - try again in %ds" % left)
        if not has_password():
            return self.fail(400, "no password has been set")
        if not check_password(str(data.get("password", ""))):
            note_login(ip, False)
            return self.fail(401, "wrong password")
        note_login(ip, True)
        token = new_session()
        return self.json({"ok": True}, extra={
            "Set-Cookie": "webscan_session=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict"
                          % (token, SESSION_TTL)})

    def change_password(self, data: dict):
        new = str(data.get("new", ""))
        if has_password():
            if not self.authed():
                return self.fail(401, "login required")
            if not check_password(str(data.get("current", ""))):
                return self.fail(401, "wrong current password")
        try:
            set_password(new)
        except ValueError as exc:
            return self.fail(400, str(exc))
        token = new_session()
        return self.json({"ok": True}, extra={
            "Set-Cookie": "webscan_session=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict"
                          % (token, SESSION_TTL)})

    # -- static files --------------------------------------------------
    def serve_static(self, rel: str):
        safe = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not safe.startswith(STATIC_DIR + os.sep) or not os.path.isfile(safe):
            return self.fail(404, "not found")
        ctype = {".html": "text/html; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8",
                 ".svg": "image/svg+xml"}.get(os.path.splitext(safe)[1],
                                              "application/octet-stream")
        with open(safe, "rb") as fh:
            body = fh.read()
        if safe.endswith(".html"):
            body = versioned(body)
        self._send(200, body, ctype, {"Cache-Control": "no-cache"})


_ASSET_RE = re.compile(rb'"/static/([\w.-]+\.(?:css|js))"')


def versioned(html: bytes) -> bytes:
    """Give the page's stylesheet and script a ?v=<mtime> in their URL. A
    browser holding an old copy then fetches the new one after an update,
    instead of running last week's script against today's API."""
    def sub(m: re.Match) -> bytes:
        try:
            stamp = int(os.path.getmtime(os.path.join(STATIC_DIR, m.group(1).decode())))
        except OSError:
            return m.group(0)
        return b'"/static/%s?v=%d"' % (m.group(1), stamp)
    return _ASSET_RE.sub(sub, html)


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
PROBE_MODE = "?"


def main() -> None:
    global store, eng, PROBE_MODE

    ap = argparse.ArgumentParser(description="WebScan - network scanner with a web UI")
    ap.add_argument("--host", default="127.0.0.1",
                    help="listen address (0.0.0.0 for the whole network)")
    ap.add_argument("--port", type=int, default=8422)
    ap.add_argument("--set-password", action="store_true",
                    help="set the password that protects scanning and settings, then exit")
    args = ap.parse_args()

    if args.set_password:
        first = getpass.getpass("New password: ")
        again = getpass.getpass("Repeat: ")
        if first != again:
            sys.exit("the passwords do not match")
        set_password(first)
        print("password stored in %s" % AUTH_PATH)
        return

    PROBE_MODE = scanner.selftest()
    cfg = load_config()
    oui.configure(cfg["oui_dir"])
    store = Store(DB_PATH)
    eng = engine_mod.Engine(store, cfg)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    shown = "127.0.0.1" if args.host in ("", "0.0.0.0") else args.host
    print("[webscan] %s, %d MAC prefixes known" % (PROBE_MODE, oui.size()), flush=True)
    print("[webscan] web UI on http://%s:%d" % (shown, args.port), flush=True)
    if not has_password():
        print("[webscan] no password set - anyone who can reach this can start scans."
              " Run: python3 webscan.py --set-password", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[webscan] stopping ...")
    finally:
        eng.shutdown()
        srv.server_close()
        store.close()


if __name__ == "__main__":
    main()
