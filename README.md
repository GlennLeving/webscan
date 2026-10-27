# WebScan

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

Network scanner with a web UI — Advanced IP Scanner in the browser. WebScan scans
one or more subnets and lists every host it finds with its **address, name, MAC,
manufacturer, ping time, open ports and what is behind them**. Every scan is kept,
so the next one shows which hosts are **new** and which are **gone**.

No dependencies — Python 3 standard library only. No root needed on Linux.

## Install

```
git clone https://github.com/GlennLeving/webscan.git
cd webscan
python3 webscan.py --set-password     # optional: protect scanning and settings
./start.sh
```

Then open <http://127.0.0.1:8422>, check the targets in the top bar and press **Scan**.

## Start

```
./start.sh                      # http://127.0.0.1:8422
./start.sh --host 0.0.0.0       # reachable from other machines
./start.sh --port 9000
```

## What you can scan

The scan field takes any mix of these, separated by spaces or commas:

| Form | Example |
|---|---|
| Subnet | `192.168.100.0/24` |
| Range | `192.168.100.10-50` or `10.0.0.1-10.0.1.254` |
| Single address | `192.168.65.170` |

At most `max_hosts` addresses per scan (default 1024).

## How it works

A scan runs in phases; the progress bar shows which one it is in.

1. **Ping.** One ICMP echo to every address, all sent at once over a single
   socket, in two rounds so one lost packet does not hide a host. Round trip times
   come from the kernel's receive timestamp, so they stay accurate even though
   hundreds of replies arrive at once.
2. **ARP.** On a directly attached subnet the ping has also made the kernel ARP
   for every address. A host answers ARP even when its firewall drops ping —
   Windows does by default — so the neighbour table (`ip neigh`) finds those too,
   and gives the MAC of every host. WebScan waits until the kernel has *settled*
   each entry rather than trusting the cache: a `STALE` entry can describe a
   machine that left hours ago.
3. **Ports.** A TCP connect to each of `ports` on every host found. On a routed
   subnet, where there is no ARP to ask, silent addresses first get the few
   `discovery_ports`: a refused connection proves a host is there just as well as
   an open one.
4. **Names.** PTR queries sent straight to `dns_servers` (by default
   192.168.65.170 and .172). The system resolver is bypassed on purpose: it does not
   resolve the `.local` domain reliably. Every host is also asked over NetBIOS
   (UDP 137), which most Windows machines and many printers answer; that name is
   used when there is no PTR record, and tagged `nb`. NetBIOS also gives a MAC address for hosts
   across a router.
5. **Details.** The title of the web page on open HTTP/HTTPS ports, and the
   greeting banner of ssh, ftp, smtp, pop3 and imap. On printers, cameras and
   controllers this usually says exactly what the device is.

The manufacturer comes from the MAC address and the IEEE registry in
`/usr/share/ieee-data` (package `ieee-data`), longest prefix first. A MAC with the
"locally administered" bit set is shown as *(randomized MAC)* — phones and laptops
use one per Wi-Fi network, so it has no manufacturer. Refresh the registry with
`sudo update-ieee-data`.

## Reading the results

| Column | Meaning |
|---|---|
| ● | Green: answers ping. Amber: there, but only answers ARP or TCP |
| IP | Address. `NEW` / `GONE` against the scan it is compared with; `MOVED` when the same MAC had another address |
| Name | Reverse DNS, or NetBIOS (`nb`) |
| MAC / Manufacturer | From ARP, or from NetBIOS across a router |
| Ping | Round trip, or `no` |
| Services | Open ports. Web and FTP ports are links; hover for the page title or banner |
| First seen | When WebScan first saw this host in any scan |

Click a row for the details: how the host was found, the name source, its
workgroup or domain, and every service with its title or banner.

**Search** matches every column, including service titles — `canon`, `9100`,
`rdp`, `iis` and `stansomatic` all work. Several words must all match. Click a
column heading to sort. The filters show all current hosts, only new, only gone,
or only hosts with open ports.

### New and gone

A scan is compared with the previous **complete** scan of exactly the same
targets — a stopped scan is missing hosts it never reached, so it is never the
baseline. Pick another scan in *Compare with* to look further back.

Hosts are matched by MAC and address, then by MAC alone (it moved — DHCP gave it
another address), then by address alone (no MAC, e.g. behind a router). Matching
on the address alone would call every DHCP shuffle one host gone and one new.

## Export to CSV

* **Export CSV** in the toolbar saves exactly the rows shown — after search,
  filter and sorting. Pick the *Gone* filter and export to get a list of what
  disappeared.
* **CSV (all)** saves every host in the scan plus the gone ones, from
  `GET /api/export.csv?id=N`.

Columns: `status, ip, name, mac, vendor, ping_ms, found_by, open_ports, services,
workgroup, first_seen`. The file is UTF-8 with a BOM, so Excel opens it with the
right characters.

## Settings

| Field | Meaning |
|---|---|
| `default_targets` | What the scan field is filled with, and what scheduled scans scan |
| `ports` | TCP ports checked on every host |
| `discovery_ports` | Ports tried on silent addresses on routed subnets |
| `dns_servers` | Servers asked for PTR records; empty = the system resolver |
| `resolve_names` / `netbios` / `http_titles` | Turn those phases on or off |
| `ping_timeout` / `ping_rounds` | How long to wait for echo replies, and how many rounds |
| `arp_wait_seconds` | Longest wait for the neighbour table to settle |
| `connect_timeout` | TCP connect timeout per port |
| `dns_timeout` / `detail_timeout` | Timeouts for name lookups and for reading titles and banners |
| `threads` | Parallel TCP connections |
| `max_hosts` | Largest scan allowed |
| `schedule_minutes` | Scan `default_targets` automatically this often; 0 = off |
| `keep_scans` | Older scans are deleted |
| `oui_dir` | Where the IEEE registry files are |

Changes made in the UI are written to `config.json` and take effect from the next
scan. See `config.example.json` for the defaults.

## Password

The results are open to anyone who can reach WebScan, but **starting or stopping
a scan, deleting a scan and changing settings require a login**. With no password
set, everything is open — set one from the UI or:

```
python3 webscan.py --set-password
```

* Stored only as a PBKDF2 hash (240,000 rounds, random salt) in `auth.json`
  (chmod 600) — never in clear text, and never in `config.json`.
* A login yields a random session cookie (HttpOnly, SameSite=Strict) valid for
  12 hours.
* 5 failed attempts from one IP block that IP for 5 minutes.

Forgot it? Delete `auth.json` and set a new one.

> Note: traffic is plain HTTP, so the password crosses the network unencrypted.
> Do not reuse a password from elsewhere.

## Data

`webscan.db` (sqlite, WAL mode):

* `scans` — one row per scan: targets, times, status, hosts found, new and gone.
* `results` — one row per host per scan.
* `seen` — first and last time each host (by MAC, else by address) was seen.

Query directly:

```
sqlite3 webscan.db "SELECT ip, name, vendor FROM results WHERE scan_id=(SELECT MAX(id) FROM scans WHERE status='done') ORDER BY ipnum;"
```

## API

| Endpoint | Description |
|---|---|
| `GET /api/state` | Running scan and its progress, the scan list, settings |
| `GET /api/scans?limit=N` | Scan list |
| `GET /api/scan?id=N&vs=M` | Hosts of scan N marked new against scan M (default: the previous one), plus the gone ones. No `id` = the latest |
| `GET /api/export.csv?id=N&vs=M` | The same as CSV |
| `POST /api/scan/start` | `{"targets": "192.168.100.0/24"}` — returns `{"id": N}` |
| `POST /api/scan/stop` | Stop the running scan; what was found so far is kept, marked *stopped* |
| `POST /api/scan/delete` | `{"id": N}` |
| `GET` / `POST /api/config` | Read and write settings |
| `POST /api/login` / `POST /api/logout` | `{"password": "..."}` — sets a session cookie |
| `GET /api/session` | `{authed, protected, lockout}` |
| `POST /api/set-password` | `{"current": "...", "new": "..."}` |
| `GET /api/status` | Health check for `update.sh` |

Everything that changes state requires a login when a password is set.

## Run as a background service (systemd)

```
cp webscan.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now webscan
loginctl enable-linger $USER          # keep running when logged out
journalctl --user -u webscan -f       # follow the log
```

The unit runs with `ProtectSystem=strict` and may only write inside `~/webscan`.
To change the port or listen address, edit `ExecStart` and run
`systemctl --user daemon-reload && systemctl --user restart webscan`.

## Behind nginx

`nginx-webscan.conf` publishes WebScan as `http://webscan.stansomatic.local`:

```
sudo cp nginx-webscan.conf /etc/nginx/sites-available/webscan.conf
sudo ln -s /etc/nginx/sites-available/webscan.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The name also needs an A record in DNS pointing at this server. WebScan reads the
real client address from `X-Forwarded-For` (trusted from loopback only), so the
login lockout still works per client behind the proxy.

## Updating

`update.sh` fetches the latest code, restarts the service and checks that it
actually came back:

```
./update.sh
```

It refuses to run while the working tree has uncommitted changes, syntax-checks
the new code before restarting, and if the service does not answer afterwards it
resets to the previous commit and restarts again. `config.json`, `auth.json` and
the database are ignored by git and are never touched.

## Notes

* **Only scan networks you are responsible for.** A port scan is noisy, and an
  IDS will notice it.
* The neighbour table holds 1024 entries by default (`gc_thresh3`). A directly
  attached subnet larger than that will overflow it while scanning — scan it in
  parts.
* IPv4 only.

## License

MIT — see [LICENSE](LICENSE). Author: Glenn Leving.
