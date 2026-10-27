#!/usr/bin/env python3
"""
scanner.py - the network scan itself, for WebScan.

A scan runs in phases:

  ping     ICMP echo to every address at once, over one ping socket. Two
           rounds, so a single lost packet does not hide a host.
  arp      On a directly attached subnet the ping has also made the kernel
           ARP for every address. A host answers ARP even when its firewall
           drops ping (Windows does by default), so the neighbour table
           finds those too. We wait for the kernel to settle each entry
           rather than trust what is cached: a STALE entry can be hours old.
  ports    TCP connect to a list of ports on every host found. A refused
           connection also proves the host is there, so silent addresses on
           routed subnets (no ARP to ask) get a few discovery ports first.
  names    PTR queries sent straight to the configured DNS servers - the
           system resolver cannot be trusted with a .local domain - and a
           NetBIOS node status query, which names Windows machines with no
           PTR record and gives a MAC across a router.
  details  HTTP page titles and the greeting banner of ssh, ftp, smtp and the
           like, which usually say what a device is.

No dependencies and no root: Linux ping sockets are open to every uid in
net.ipv4.ping_group_range, and everything else is ordinary TCP and UDP. The
neighbour table is read with `ip -j neigh`.

Author: Glenn Leving
"""

from __future__ import annotations

__author__ = "Glenn Leving"

import concurrent.futures as cf
import errno
import http.client
import ipaddress
import json
import os
import random
import re
import select
import socket
import ssl
import struct
import subprocess
import time
from typing import Callable

import oui

# Names for the ports we look at. /etc/services knows most of these, but
# not by the names an administrator expects (9100 is "jetdirect", not "hp-pdl").
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 515: "lpd", 548: "afp", 554: "rtsp",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1883: "mqtt", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 8000: "http", 8006: "proxmox",
    8080: "http", 8081: "http", 8443: "https", 8888: "http", 9100: "jetdirect",
}
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
HTTPS_PORTS = {443, 4443, 8006, 8443}
BANNER_PORTS = {21, 22, 25, 110, 143}       # the server speaks first

PING_PAYLOAD = b"webscan-" + bytes(range(24))
SO_TIMESTAMPNS = 35                          # Linux; not exposed by the socket module

Progress = Callable[[str, int, int], None]
Stopped = Callable[[], bool]


def service_name(port: int) -> str:
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------
def parse_targets(text: str, max_hosts: int) -> tuple[list[str], str]:
    """Turn '192.168.100.0/24, 10.0.0.5-20 10.0.1.7' into a list of
    addresses, plus a normalised form of the text. The normalised form is what
    tells two scans of the same thing apart from two scans of different things,
    so new and gone hosts are only ever counted between comparable scans."""
    tokens = [t for t in re.split(r"[\s,;]+", text.strip()) if t]
    if not tokens:
        raise ValueError("nothing to scan - give a subnet, a range or an address")
    seen: dict[int, None] = {}
    norm: list[str] = []
    for tok in tokens:
        try:
            if "/" in tok:
                net = ipaddress.IPv4Network(tok, strict=False)
                if net.num_addresses > max_hosts + 2:
                    raise ValueError("%s has %d addresses - the limit is %d"
                                     % (net, net.num_addresses, max_hosts))
                addrs = list(net.hosts()) if net.prefixlen < 31 else list(net)
                norm.append(str(net))
            elif "-" in tok:
                left, right = tok.split("-", 1)
                first = ipaddress.IPv4Address(left)
                if "." not in right:
                    right = left.rsplit(".", 1)[0] + "." + right
                last = ipaddress.IPv4Address(right)
                if last < first:
                    raise ValueError("%s: the range runs backwards" % tok)
                if int(last) - int(first) + 1 > max_hosts:
                    raise ValueError("%s is more than %d addresses" % (tok, max_hosts))
                addrs = [ipaddress.IPv4Address(n) for n in range(int(first), int(last) + 1)]
                norm.append("%s-%s" % (first, last))
            else:
                addrs = [ipaddress.IPv4Address(tok)]
                norm.append(str(addrs[0]))
        except ipaddress.AddressValueError:
            raise ValueError("'%s' is not an IPv4 address, subnet or range" % tok) from None
        except ipaddress.NetmaskValueError:
            raise ValueError("'%s' has an invalid prefix length" % tok) from None
        for a in addrs:
            if a.is_multicast or a.is_unspecified or a.is_loopback or int(a) == 0xFFFFFFFF:
                continue
            seen[int(a)] = None
        if len(seen) > max_hosts:
            raise ValueError("more than %d addresses in total - scan fewer at a time" % max_hosts)
    if not seen:
        raise ValueError("no scannable addresses in '%s'" % text.strip())
    return [str(ipaddress.IPv4Address(n)) for n in seen], " ".join(norm)


def ipnum(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


# --------------------------------------------------------------------------
# Local interfaces and the neighbour table
# --------------------------------------------------------------------------
def _ip_json(*args: str) -> list:
    try:
        out = subprocess.run(["ip", "-j", *args], capture_output=True,
                             text=True, timeout=5, check=False).stdout
        return json.loads(out or "[]")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def local_interfaces() -> list[dict]:
    """[{dev, ip, net, mac}] for every IPv4 address on this machine."""
    out = []
    for link in _ip_json("-4", "addr", "show"):
        dev = link.get("ifname", "")
        if dev == "lo":
            continue
        try:
            with open("/sys/class/net/%s/address" % dev, "r", encoding="ascii") as fh:
                mac = fh.read().strip().upper()
        except OSError:
            mac = ""
        for a in link.get("addr_info", []):
            if a.get("family") != "inet":
                continue
            net = ipaddress.IPv4Network("%s/%s" % (a["local"], a["prefixlen"]), strict=False)
            out.append({"dev": dev, "ip": a["local"], "net": net, "mac": mac})
    return out


def neighbours() -> dict[str, tuple[str, str]]:
    """{ip: (MAC, state)} from the kernel's neighbour table."""
    table = {}
    for n in _ip_json("-4", "neigh", "show"):
        state = (n.get("state") or ["NONE"])[0]
        table[n.get("dst", "")] = ((n.get("lladdr") or "").upper(), state)
    return table


# The kernel is still finding out about these. Anything else is a verdict.
UNSETTLED = {"INCOMPLETE", "DELAY", "PROBE"}


# --------------------------------------------------------------------------
# ICMP
# --------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class Pinger:
    """Echo requests to many hosts over one socket. A ping socket when the
    kernel allows it (no root), otherwise a raw socket (root or cap_net_raw)."""

    def __init__(self):
        self.ident = random.randrange(1, 0xFFFF)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            self.raw = False
        except OSError:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.raw = True
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        # Let the kernel stamp each reply on arrival. We send hundreds of
        # packets in a burst and read replies in between, so the time we get
        # round to reading one says nothing about when it came back.
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        except OSError:
            pass
        self.sock.setblocking(False)

    def send(self, ip: str, seq: int) -> None:
        head = struct.pack("!BBHHH", 8, 0, 0, self.ident, seq & 0xFFFF)
        if self.raw:
            csum = _checksum(head + PING_PAYLOAD)
            head = struct.pack("!BBHHH", 8, 0, csum, self.ident, seq & 0xFFFF)
        try:
            self.sock.sendto(head + PING_PAYLOAD, (ip, 0))
        except OSError:
            pass                      # no route, or ARP already failed: no answer

    def drain(self, timeout: float) -> list[tuple[str, float]]:
        """(address, arrival time.time()) of every echo reply within `timeout`
        seconds."""
        got = []
        ready, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        while ready:
            try:
                pkt, anc, _flags, (src, _port) = self.sock.recvmsg(2048, 64)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            stamp = time.time()
            for level, kind, data in anc:
                if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS and len(data) >= 16:
                    sec, nsec = struct.unpack("@qq", data[:16])
                    stamp = sec + nsec / 1e9
            if self.raw:
                pkt = pkt[(pkt[0] & 0x0F) * 4:]
            if len(pkt) >= 8 and pkt[0] == 0:
                if self.raw and struct.unpack("!H", pkt[4:6])[0] != self.ident:
                    continue
                got.append((src, stamp))
        return got

    def close(self) -> None:
        self.sock.close()


def selftest() -> str:
    """One line for the startup log and the UI, saying how ICMP is sent."""
    try:
        p = Pinger()
    except OSError as exc:
        return "no ICMP (%s) - hosts are found by ARP and TCP only" % exc.strerror
    mode = "raw socket" if p.raw else "ping socket, no root"
    p.close()
    return "ICMP via %s" % mode


def ping_sweep(addrs: list[str], timeout: float, rounds: int,
               progress: Progress, stopped: Stopped) -> dict[str, float]:
    """{ip: round trip ms} for every address that answered."""
    try:
        pinger = Pinger()
    except OSError:
        return {}
    alive: dict[str, float] = {}
    sent_at: dict[str, float] = {}
    try:
        for rnd in range(rounds):
            todo = [a for a in addrs if a not in alive]
            for i, ip in enumerate(todo):
                if stopped():
                    return alive
                sent_at[ip] = time.time()
                pinger.send(ip, rnd * 65536 + i)
                # Read as we go, so a big subnet cannot overflow the receive
                # buffer and so the round trip times stay honest.
                if i % 32 == 31:
                    for src, at in pinger.drain(0):
                        if src in sent_at and src not in alive:
                            alive[src] = max(0.0, at - sent_at[src]) * 1000
                    time.sleep(0.002)
                    progress("ping", rnd * len(addrs) + len(addrs) - len(todo) + i, rounds * len(addrs))
            end = time.monotonic() + timeout
            while time.monotonic() < end and not stopped():
                for src, at in pinger.drain(end - time.monotonic()):
                    if src in sent_at and src not in alive:
                        alive[src] = max(0.0, at - sent_at[src]) * 1000
            progress("ping", (rnd + 1) * len(addrs), rounds * len(addrs))
    finally:
        pinger.close()
    return alive


def arp_nudge(addrs: list[str]) -> None:
    """Make the kernel ARP for each address without ICMP: a UDP packet to the
    discard port. Only used when no ICMP socket could be opened."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for ip in addrs:
            try:
                s.sendto(b"", (ip, 9))
            except OSError:
                pass


def arp_settle(addrs: list[str], deadline: float, stopped: Stopped,
               progress: Progress) -> dict[str, tuple[str, str]]:
    """Wait until the kernel has decided about every address in `addrs`, or
    until `deadline`, and return the neighbour table for them."""
    want = set(addrs)
    while True:
        table = {ip: v for ip, v in neighbours().items() if ip in want}
        open_ = [ip for ip, (_mac, st) in table.items() if st in UNSETTLED]
        progress("arp", len(want) - len(open_), len(want))
        if not open_ or time.monotonic() >= deadline or stopped():
            return table
        time.sleep(0.5)


# --------------------------------------------------------------------------
# TCP
# --------------------------------------------------------------------------
def tcp_probe(ip: str, port: int, timeout: float) -> str:
    """'open', 'closed' (refused - but the host is there) or '' (no answer)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        err = s.connect_ex((ip, port))
    except OSError:
        return ""
    finally:
        s.close()
    if err == 0:
        return "open"
    if err == errno.ECONNREFUSED:
        return "closed"
    return ""


def port_scan(jobs: list[tuple[str, int]], timeout: float, threads: int,
              phase: str, progress: Progress, stopped: Stopped) -> dict[str, dict]:
    """{ip: {"open": set(ports), "answered": bool}} for the (ip, port) pairs."""
    out: dict[str, dict] = {}
    if not jobs:
        return out
    done = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futs = {pool.submit(tcp_probe, ip, port, timeout): (ip, port) for ip, port in jobs}
        try:
            for fut in cf.as_completed(futs):
                ip, port = futs[fut]
                res = fut.result()
                rec = out.setdefault(ip, {"open": set(), "answered": False})
                if res:
                    rec["answered"] = True
                if res == "open":
                    rec["open"].add(port)
                done += 1
                if done % 25 == 0 or done == len(jobs):
                    progress(phase, done, len(jobs))
                if stopped():
                    for f in futs:
                        f.cancel()
                    break
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
    return out


# --------------------------------------------------------------------------
# DNS (PTR), spoken directly so we can pick the server
# --------------------------------------------------------------------------
def _dns_name(labels: str) -> bytes:
    out = b""
    for part in labels.strip(".").split("."):
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"


def _read_name(buf: bytes, i: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name at i. Returns the name and the
    offset just after it in the original position."""
    parts: list[str] = []
    end = None
    hops = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated name")
        n = buf[i]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = i + 2
            i = ((n & 0x3F) << 8) | buf[i + 1]
            hops += 1
            if hops > 20:
                raise ValueError("pointer loop")
            continue
        if n == 0:
            i += 1
            break
        parts.append(buf[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(parts), (end if end is not None else i)


def _query(txid: int, qname: str, qtype: int) -> bytes:
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + _dns_name(qname) + struct.pack("!HH", qtype, 1))


def _answers(pkt: bytes) -> tuple[int, int, list[tuple[int, str]]]:
    """(txid, rcode, [(type, value)]) from a response. PTR and CNAME values
    are names, A values are addresses; other types are skipped."""
    txid, flags, qd, an = struct.unpack("!HHHH", pkt[:8])
    i = 12
    for _ in range(qd):
        _, i = _read_name(pkt, i)
        i += 4
    out = []
    for _ in range(an):
        _, i = _read_name(pkt, i)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", pkt[i:i + 10])
        i += 10
        if rtype in (5, 12):
            out.append((rtype, _read_name(pkt, i)[0]))
        elif rtype == 1 and rdlen == 4:
            out.append((rtype, socket.inet_ntoa(pkt[i:i + 4])))
        i += rdlen
    return txid, flags & 0x0F, out


def _dns_bulk(queries: dict[str, tuple[str, int]], servers: list[str], timeout: float,
              stopped: Stopped) -> dict[str, tuple[int, list[tuple[int, str]]]]:
    """Send every query at once and collect {key: (rcode, answers)}. A key
    that a server did not answer at all - as opposed to answering 'no such
    name' - is asked again at the next server. Keys no server answered are
    missing from the result."""
    got: dict[str, tuple[int, list[tuple[int, str]]]] = {}
    todo = list(queries)
    for server in servers:
        if not todo or stopped():
            break
        base = random.randrange(0, 0x10000)
        by_id = {(base + k) & 0xFFFF: key for k, key in enumerate(todo)}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(False)
            for txid, key in by_id.items():
                qname, qtype = queries[key]
                try:
                    s.sendto(_query(txid, qname, qtype), (server, 53))
                except (OSError, UnicodeEncodeError, ValueError):
                    continue
            end = time.monotonic() + timeout
            answered = 0
            while answered < len(by_id) and time.monotonic() < end:
                ready, _, _ = select.select([s], [], [], max(0.0, end - time.monotonic()))
                if not ready:
                    break
                try:
                    pkt, (src, _p) = s.recvfrom(4096)
                except OSError:
                    continue
                if src != server or len(pkt) < 12:
                    continue
                try:
                    txid, rcode, answers = _answers(pkt)
                except (ValueError, struct.error, IndexError):
                    continue
                key = by_id.get(txid)
                if key is None or key in got:
                    continue
                got[key] = (rcode, answers)
                answered += 1
        todo = [k for k in todo if k not in got]
    return got


def reverse_dns(addrs: list[str], servers: list[str], timeout: float,
                stopped: Stopped) -> dict[str, str]:
    """{ip: name} from PTR records."""
    names: dict[str, str] = {}
    if not servers:
        for ip in addrs:
            if stopped():
                break
            try:
                names[ip] = socket.gethostbyaddr(ip)[0]
            except OSError:
                pass
        return names
    queries = {ip: (".".join(reversed(ip.split("."))) + ".in-addr.arpa", 12) for ip in addrs}
    for ip, (rcode, answers) in _dns_bulk(queries, servers, timeout, stopped).items():
        ptr = [v for t, v in answers if t == 12]
        if rcode == 0 and ptr:
            names[ip] = ptr[0].rstrip(".")
    return names


def forward_dns(names: list[str], servers: list[str], timeout: float,
                stopped: Stopped) -> dict[str, list[str] | None]:
    """{name (lower case): [addresses]} from A records, following CNAMEs
    within the answer. [] = the name does not resolve. Names no server
    answered for are missing, so 'could not check' never looks like
    'does not resolve'."""
    uniq = sorted({n.lower().rstrip(".") for n in names if n})
    out: dict[str, list[str] | None] = {}
    if not servers:
        for name in uniq:
            if stopped():
                break
            try:
                out[name] = sorted(set(socket.gethostbyname_ex(name)[2]))
            except socket.gaierror as exc:
                if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
                    out[name] = []
            except OSError:
                pass
        return out
    for name, (rcode, answers) in _dns_bulk({n: (n, 1) for n in uniq}, servers, timeout, stopped).items():
        if rcode == 0:
            out[name] = sorted({v for t, v in answers if t == 1})
        elif rcode == 3:                  # NXDOMAIN
            out[name] = []
        # SERVFAIL, REFUSED and the like say nothing about the name.
    return out


def name_check(ip: str, name: str, forward: dict[str, list[str] | None]) -> tuple[str, list[str]]:
    """Does the PTR name of `ip` point back to it? ('ok' | 'mismatch' |
    'missing' | '' when it could not be checked, forward addresses)."""
    key = name.lower().rstrip(".")
    if key not in forward:
        return "", []
    addrs = forward[key] or []
    if ip in addrs:
        return "ok", addrs
    return ("mismatch" if addrs else "missing"), addrs


# --------------------------------------------------------------------------
# NetBIOS node status (UDP 137)
# --------------------------------------------------------------------------
# The name '*' in NetBIOS first-level encoding: each nibble + 'A', padded to
# 16 bytes with NULs.
_NB_STAR = b"\x20" + b"CK" + b"A" * 30 + b"\x00"


def _nb_query(txid: int) -> bytes:
    return struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + _NB_STAR + struct.pack("!HH", 0x21, 1)


def _nb_skip_name(pkt: bytes, i: int) -> int:
    while i < len(pkt):
        n = pkt[i]
        if n & 0xC0 == 0xC0:
            return i + 2
        if n == 0:
            return i + 1
        i += 1 + n
    raise ValueError("truncated name")


def _nb_parse(pkt: bytes) -> dict:
    """{name, group, mac} from a node status response."""
    qd, an = struct.unpack("!HH", pkt[4:8])
    i = 12
    for _ in range(qd):
        i = _nb_skip_name(pkt, i) + 4
    if an < 1:
        return {}
    i = _nb_skip_name(pkt, i)
    rtype, _cls, _ttl, _rdlen = struct.unpack("!HHIH", pkt[i:i + 10])
    i += 10
    if rtype != 0x21:
        return {}
    count = pkt[i]
    i += 1
    name = group = ""
    for _ in range(count):
        entry = pkt[i:i + 18]
        if len(entry) < 18:
            break
        label = entry[:15].decode("latin-1").strip()
        suffix = entry[15]
        is_group = bool(struct.unpack("!H", entry[16:18])[0] & 0x8000)
        if suffix == 0x00 and not is_group and not name:
            name = label
        elif suffix == 0x00 and is_group and not group:
            group = label
        i += 18
    mac = pkt[i:i + 6]
    mac_s = ":".join("%02X" % b for b in mac) if len(mac) == 6 and any(mac) else ""
    return {"name": name, "group": group, "mac": mac_s}


def netbios(addrs: list[str], timeout: float, stopped: Stopped) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not addrs:
        return out
    base = random.randrange(0, 0x10000)
    by_id = {(base + k) & 0xFFFF: ip for k, ip in enumerate(addrs)}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        for txid, ip in by_id.items():
            try:
                s.sendto(_nb_query(txid), (ip, 137))
            except OSError:
                pass
        end = time.monotonic() + timeout
        while len(out) < len(by_id) and time.monotonic() < end and not stopped():
            ready, _, _ = select.select([s], [], [], max(0.0, end - time.monotonic()))
            if not ready:
                break
            try:
                pkt, (src, _p) = s.recvfrom(4096)
            except OSError:
                continue          # ICMP port unreachable from an earlier send
            if len(pkt) < 12:
                continue
            ip = by_id.get(struct.unpack("!H", pkt[:2])[0])
            if ip != src:
                continue
            try:
                rec = _nb_parse(pkt)
            except (ValueError, struct.error, IndexError):
                continue
            if rec.get("name") or rec.get("mac"):
                out[ip] = rec
    return out


# --------------------------------------------------------------------------
# What is behind an open port
# --------------------------------------------------------------------------
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_PRINTABLE = re.compile(r"[^\x20-\x7E -￿]")


def _clean(text: str, limit: int = 120) -> str:
    text = " ".join(_PRINTABLE.sub(" ", text).split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _tls_context() -> ssl.SSLContext:
    # Printers and switches still serve self-signed certificates and old TLS.
    # We only read a page title, so nothing is lost by not checking.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def http_info(ip: str, port: int, tls: bool, timeout: float) -> str:
    try:
        if tls:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=_tls_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={"User-Agent": "WebScan", "Accept": "text/html"})
            resp = conn.getresponse()
            body = resp.read(65536)
            server = resp.getheader("Server", "") or ""
            title = ""
            m = _TITLE_RE.search(body)
            if m:
                title = m.group(1).decode(resp.headers.get_content_charset() or "utf-8", "replace")
                title = _clean(re.sub(r"&nbsp;|&#160;", " ", title))
            parts = [title or ""]
            if 300 <= resp.status < 400 and resp.getheader("Location"):
                parts.append("-> " + _clean(resp.getheader("Location"), 80))
            elif resp.status >= 400 and not title:
                parts.append("HTTP %d" % resp.status)
            if server:
                parts.append("[%s]" % _clean(server, 60))
            return " ".join(p for p in parts if p)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ValueError):
        return ""


def banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            data = s.recv(256)
    except OSError:
        return ""
    line = data.split(b"\n", 1)[0].decode("latin-1", "replace")
    return _clean(line, 100)


def port_info(ip: str, port: int, timeout: float, http_titles: bool) -> str:
    if http_titles and port in HTTPS_PORTS:
        return http_info(ip, port, True, timeout)
    if http_titles and port in HTTP_PORTS:
        return http_info(ip, port, False, timeout)
    if port in BANNER_PORTS:
        return banner(ip, port, timeout)
    return ""


# --------------------------------------------------------------------------
# The whole scan
# --------------------------------------------------------------------------
def scan(addrs: list[str], cfg: dict, progress: Progress, stopped: Stopped) -> list[dict]:
    """Scan `addrs` and return one dict per host found, sorted by address:
    {ip, mac, vendor, name, name_src, workgroup, via, rtt, ports, self}."""
    oui.configure(cfg["oui_dir"])
    ifaces = local_interfaces()
    own = {i["ip"]: i for i in ifaces}
    onlink = [a for a in addrs
              if a not in own and any(ipaddress.IPv4Address(a) in i["net"] for i in ifaces)]
    onlink_set = set(onlink)
    t0 = time.monotonic()

    hosts: dict[str, dict] = {}

    def host(ip: str) -> dict:
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "mac": "", "vendor": "", "name": "", "name_src": "",
                         "name_check": "", "name_fwd": [], "workgroup": "", "via": [],
                         "rtt": None, "ports": [], "self": False}
        return hosts[ip]

    for ip in addrs:
        if ip in own:
            h = host(ip)
            h["self"], h["mac"], h["via"] = True, own[ip]["mac"], ["self"]

    # -- ping ---------------------------------------------------------
    progress("ping", 0, len(addrs))
    rtts = ping_sweep([a for a in addrs if a not in own], cfg["ping_timeout"],
                      cfg["ping_rounds"], progress, stopped)
    if not rtts and onlink and not stopped():
        arp_nudge(onlink)
    for ip, rtt in rtts.items():
        h = host(ip)
        h["rtt"] = round(rtt, 2)
        h["via"].append("ping")

    # -- arp ----------------------------------------------------------
    if onlink and not stopped():
        table = arp_settle(onlink, t0 + cfg["arp_wait_seconds"], stopped, progress)
        for ip, (mac, state) in table.items():
            if not mac or state in ("FAILED", "INCOMPLETE", "NONE"):
                continue
            if state in ("REACHABLE", "PERMANENT"):
                host(ip)["via"].append("arp")
            if ip in hosts:
                hosts[ip]["mac"] = mac

    # -- ports --------------------------------------------------------
    ports = sorted(set(cfg["ports"]))
    if cfg["discovery_ports"] and not stopped():
        # Silent addresses on routed subnets: nothing has asked them
        # anything they would answer yet.
        silent = [a for a in addrs if a not in hosts and a not in onlink_set and a not in own]
        disc = sorted(set(cfg["discovery_ports"]))
        res = port_scan([(ip, p) for ip in silent for p in disc], cfg["connect_timeout"],
                        cfg["threads"], "discovery", progress, stopped)
        for ip, rec in res.items():
            if rec["answered"]:
                h = host(ip)
                h["via"].append("tcp")
                h["_open"] = set(rec["open"])
    if ports and not stopped():
        jobs = [(ip, p) for ip in sorted(hosts, key=ipnum) for p in ports
                if p not in hosts[ip].get("_open", ())]
        res = port_scan(jobs, cfg["connect_timeout"], cfg["threads"], "ports", progress, stopped)
        for ip, rec in res.items():
            h = hosts[ip]
            h.setdefault("_open", set()).update(rec["open"])
            if rec["answered"] and not h["via"]:
                h["via"].append("tcp")

    # -- names --------------------------------------------------------
    found = sorted(hosts, key=ipnum)
    if cfg["resolve_names"] and not stopped():
        progress("names", 0, len(found))
        ptr = reverse_dns(found, cfg["dns_servers"], cfg["dns_timeout"], stopped)
        for ip, name in ptr.items():
            hosts[ip]["name"], hosts[ip]["name_src"] = name, "dns"
        # Forward-confirm each PTR name: a record left behind when a machine
        # was renamed or moved still answers, but names the wrong host.
        fwd = forward_dns(list(ptr.values()), cfg["dns_servers"], cfg["dns_timeout"], stopped)
        for ip, name in ptr.items():
            hosts[ip]["name_check"], hosts[ip]["name_fwd"] = name_check(ip, name, fwd)
        progress("names", len(found), len(found))
    if cfg["netbios"] and not stopped():
        progress("netbios", 0, len(found))
        for ip, rec in netbios(found, cfg["dns_timeout"], stopped).items():
            h = hosts[ip]
            if rec.get("name") and not h["name"]:
                h["name"], h["name_src"] = rec["name"], "netbios"
            h["workgroup"] = rec.get("group", "")
            if rec.get("mac") and not h["mac"]:
                h["mac"] = rec["mac"]
        progress("netbios", len(found), len(found))

    # -- details ------------------------------------------------------
    pairs = [(ip, p) for ip in found for p in sorted(hosts[ip].get("_open", ()))]
    info: dict[tuple[str, int], str] = {}
    if pairs and not stopped():
        with cf.ThreadPoolExecutor(max_workers=max(1, min(32, cfg["threads"]))) as pool:
            futs = {pool.submit(port_info, ip, p, cfg["detail_timeout"], cfg["http_titles"]): (ip, p)
                    for ip, p in pairs}
            done = 0
            for fut in cf.as_completed(futs):
                info[futs[fut]] = fut.result()
                done += 1
                progress("details", done, len(pairs))
                if stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

    out = []
    for ip in found:
        h = hosts[ip]
        h["ports"] = [{"port": p, "service": service_name(p), "info": info.get((ip, p), "")}
                      for p in sorted(h.pop("_open", ()))]
        h["vendor"] = oui.lookup(h["mac"]) if h["mac"] else ""
        h["via"] = ",".join(dict.fromkeys(h["via"]))
        out.append(h)
    return out
