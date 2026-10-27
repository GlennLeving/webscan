/* WebScan - frontend
 * Author: Glenn Leving
 */
'use strict';

const $ = (id) => document.getElementById(id);

const S = {
  scans: [], sel: null, vs: 0, view: null, job: null,
  cfg: {}, authed: false, protected: false,
  filter: 'all', query: '', sort: { k: 'ip', desc: false }, open: new Set(),
  lastJobId: null,
};

const PHASES = {
  starting: 'Starting', ping: 'Pinging', arp: 'Waiting for ARP', discovery: 'Probing silent addresses',
  ports: 'Checking ports', names: 'Looking up names', netbios: 'Asking NetBIOS', details: 'Reading services',
};

/* ---------- API ---------- */
async function api(path, opts) {
  const r = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
  return body;
}
const post = (p, data) => api(p, { method: 'POST', body: JSON.stringify(data || {}) });

/* ---------- formatting ---------- */
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const when = (t) => t ? new Date(t * 1000).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : '';
const day = (t) => t ? new Date(t * 1000).toLocaleDateString() : '';
const ipnum = (ip) => ip.split('.').reduce((a, b) => a * 256 + (+b), 0);
const ms = (v) => v == null ? '' : (v < 1 ? '<1' : (v < 10 ? v.toFixed(1) : Math.round(v))) + ' ms';
const dur = (s) => s < 60 ? Math.round(s) + ' s' : Math.floor(s / 60) + ' min ' + Math.round(s % 60) + ' s';

/* ---------- main loop ---------- */
async function tick() {
  try {
    const st = await api('/api/state');
    S.scans = st.scans; S.cfg = st.config; S.authed = st.authed; S.protected = st.protected;
    $('mode').textContent = st.mode;
    $('db-info').textContent = `${st.db.scans} scans stored, ${st.db.known_hosts} hosts ever seen.`;
    if (!$('targets').value && document.activeElement !== $('targets')) $('targets').value = st.config.default_targets;

    const was = S.job;
    S.job = st.job;
    renderProgress();
    // A scan just ended: show it.
    if (was && !S.job) { S.sel = was.id; S.vs = 0; S.open.clear(); await loadScan(); }
    if (S.sel === null) {
      const first = S.scans.find((s) => s.status === 'done' || s.status === 'stopped');
      if (first) { S.sel = first.id; await loadScan(); }
    }
    renderHistory();
  } catch (e) {
    $('s-sub').textContent = 'no connection to WebScan (' + e.message + ')';
  }
  setTimeout(tick, S.job ? 700 : 4000);
}

function renderProgress() {
  const j = S.job;
  $('progress').classList.toggle('hidden', !j);
  $('btn-scan').classList.toggle('hidden', !!j);
  $('btn-stop').classList.toggle('hidden', !j);
  if (!j) return;
  const pct = j.total ? Math.min(100, 100 * j.done / j.total) : 0;
  $('prog-fill').style.width = pct + '%';
  $('prog-text').textContent = `Scan #${j.id} of ${j.targets} · ${PHASES[j.phase] || j.phase}`
    + (j.total ? ` ${j.done}/${j.total}` : '') + ` · ${dur(Date.now() / 1000 - j.started)}`
    + (j.stopping ? ' · stopping ...' : '');
}

/* ---------- history ---------- */
function renderHistory() {
  const ul = $('history');
  $('side-empty').classList.toggle('hidden', S.scans.length > 0);
  ul.innerHTML = '';
  for (const s of S.scans) {
    const li = document.createElement('li');
    li.className = s.id === S.sel ? 'sel' : '';
    let line;
    if (s.status === 'running') line = '<span class="muted">running ...</span>';
    else if (s.status === 'error') line = `<span class="st-error" title="${esc(s.error)}">failed</span>`;
    else {
      line = `${s.alive} hosts`;
      if (s.new) line += ` · <span class="d-new">+${s.new}</span>`;
      if (s.gone) line += ` · <span class="d-gone">−${s.gone}</span>`;
      if (s.status === 'stopped') line += ' · <span class="st-stopped">stopped</span>';
    }
    li.innerHTML = `<div class="h-main"><b>${esc(when(s.started))}${s.trigger === 'schedule' ? ' ⏱' : ''}</b>
      <span class="small muted">${esc(s.targets)}</span><span class="small">${line}</span></div>
      <button class="h-del" title="Delete this scan">×</button>`;
    li.onclick = async (ev) => {
      if (ev.target.classList.contains('h-del')) return deleteScan(s);
      if (s.status === 'running') return;
      S.sel = s.id; S.vs = 0; S.open.clear(); renderHistory(); await loadScan();
    };
    ul.appendChild(li);
  }
}

async function deleteScan(s) {
  if (!await guard()) return;
  if (!confirm(`Delete scan #${s.id} from ${when(s.started)}?`)) return;
  try {
    await post('/api/scan/delete', { id: s.id });
    if (S.sel === s.id) { S.sel = null; S.view = null; render(); }
    S.scans = S.scans.filter((x) => x.id !== s.id); renderHistory();
  } catch (e) { alert(e.message); }
}

/* ---------- one scan ---------- */
async function loadScan() {
  if (S.sel === null) return;
  try {
    S.view = await api(`/api/scan?id=${S.sel}` + (S.vs ? `&vs=${S.vs}` : ''));
  } catch (e) { S.view = null; }
  render();
}

function rowsAll() {
  if (!S.view) return [];
  return S.view.hosts.concat(S.view.gone);
}

function matches(h, q) {
  if (!q) return true;
  const hay = [h.ip, h.name, h.mac, h.vendor, h.workgroup, h.via, h.change, h.moved_from || '']
    .concat(h.ports.map((p) => `${p.port} ${p.service} ${p.info}`)).join(' ').toLowerCase();
  return q.split(/\s+/).every((w) => hay.includes(w));
}

function visible() {
  const q = S.query.trim().toLowerCase();
  let rows = rowsAll().filter((h) => {
    if (S.filter === 'new' && h.change !== 'new') return false;
    if (S.filter === 'gone' && h.change !== 'gone') return false;
    if (S.filter === 'all' && h.change === 'gone') return false;
    if (S.filter === 'ports' && (h.change === 'gone' || !h.ports.length)) return false;
    return matches(h, q);
  });
  const { k, desc } = S.sort;
  const key = {
    ip: (h) => ipnum(h.ip),
    status: (h) => ({ new: 0, '': 1, gone: 2 }[h.change || ''] ?? 1),
    rtt: (h) => h.rtt == null ? Infinity : h.rtt,
    ports: (h) => -h.ports.length,
    first_seen: (h) => h.first_seen || 0,
  }[k] || ((h) => (h[k] || '').toLowerCase() || '￿');
  rows.sort((a, b) => {
    const x = key(a), y = key(b);
    const c = x < y ? -1 : x > y ? 1 : ipnum(a.ip) - ipnum(b.ip);
    return desc ? -c : c;
  });
  return rows;
}

function render() {
  const v = S.view;
  const sc = v && v.scan;
  $('csv-all').classList.toggle('hidden', !sc);
  if (!sc) {
    $('s-title').textContent = '-';
    $('s-sub').textContent = S.scans.length ? 'pick a scan' : 'no scans yet - press Scan';
    $('rows').innerHTML = ''; $('rows-empty').classList.remove('hidden'); $('count').textContent = '';
    $('vs').innerHTML = ''; return;
  }
  $('s-title').textContent = `Scan #${sc.id} — ${sc.targets}`;
  const took = sc.finished ? ' · took ' + dur(sc.finished - sc.started) : '';
  $('s-sub').textContent = `${when(sc.started)}${took} · ${sc.alive} of ${sc.addresses} addresses answered`
    + (sc.status === 'stopped' ? ' · stopped early, so hosts may be missing' : '')
    + (sc.status === 'error' ? ' · failed: ' + sc.error : '');

  const sel = $('vs');
  sel.innerHTML = '<option value="0">' + (v.comparable.length ? 'previous scan' : 'nothing to compare') + '</option>'
    + v.comparable.filter((c) => c.id < sc.id || S.vs === c.id)
      .map((c) => `<option value="${c.id}">#${c.id} · ${esc(when(c.started))} · ${c.alive} hosts</option>`).join('');
  sel.value = String(S.vs || 0);
  $('csv-all').href = `/api/export.csv?id=${sc.id}` + (S.vs ? `&vs=${S.vs}` : '');

  const counts = {
    all: v.hosts.length, new: v.hosts.filter((h) => h.change === 'new').length,
    gone: v.gone.length, ports: v.hosts.filter((h) => h.ports.length).length,
  };
  for (const b of $('filters').children) {
    b.classList.toggle('on', b.dataset.f === S.filter);
    b.querySelector('span').textContent = counts[b.dataset.f];
  }
  for (const th of document.querySelectorAll('.hosts th')) {
    th.classList.toggle('sorted', th.dataset.k === S.sort.k);
    th.classList.toggle('desc', th.dataset.k === S.sort.k && S.sort.desc);
  }

  const rows = visible();
  const tb = $('rows');
  const out = [];
  for (const h of rows) {
    const id = h.change === 'gone' ? 'g' + h.ip : h.ip;
    const isOpen = S.open.has(id);
    const tags = (h.change === 'new' ? '<span class="tag new">new</span>' : '')
      + (h.change === 'gone' ? '<span class="tag gone">gone</span>' : '')
      + (h.moved_from ? `<span class="tag moved" title="was ${esc(h.moved_from)}">moved</span>` : '');
    const dot = h.change === 'gone' ? '' : (h.rtt != null || h.via.includes('self') ? 'up' : 'warn');
    out.push(`<tr class="host${h.change === 'gone' ? ' gone' : ''}${isOpen ? ' open' : ''}" data-id="${esc(id)}">
      <td><span class="dot ${dot}" title="${esc(foundBy(h))}"></span></td>
      <td class="ip">${esc(h.ip)}${tags}</td>
      <td class="name" title="${esc(h.name)}">${esc(h.name)}${h.name_src === 'netbios' ? '<span class="tag nb" title="from NetBIOS, not DNS">nb</span>' : ''}</td>
      <td class="mac">${esc(h.mac)}</td>
      <td class="vendor" title="${esc(h.vendor)}">${esc(h.vendor)}</td>
      <td class="num">${h.rtt != null ? ms(h.rtt) : `<span class="muted small">${h.change === 'gone' ? '' : 'no'}</span>`}</td>
      <td class="svc"><div class="chips">${chips(h)}</div></td>
      <td class="small muted">${esc(day(h.first_seen))}</td></tr>`);
    if (isOpen) out.push(detail(h));
  }
  tb.innerHTML = out.join('');
  $('rows-empty').classList.toggle('hidden', rows.length > 0);
  $('rows-empty').textContent = rowsAll().length ? 'Nothing matches.' : 'No hosts found in this scan.';
  $('count').textContent = `${rows.length} shown`
    + (v.base ? ` · compared with scan #${v.base.id} from ${when(v.base.started)}`
      : ' · no earlier complete scan of these targets to compare with');
}

function foundBy(h) {
  const words = { ping: 'answers ping', arp: 'answers ARP', tcp: 'answers on TCP', self: 'this machine' };
  return h.via.split(',').filter(Boolean).map((w) => words[w] || w).join(', ');
}

function link(ip, p) {
  if (['https', 'proxmox'].includes(p.service) || [443, 8443, 4443, 8006].includes(p.port))
    return `https://${ip}${p.port === 443 ? '' : ':' + p.port}/`;
  if (p.service === 'http' || [80, 8080, 8000, 8081, 8888].includes(p.port))
    return `http://${ip}${p.port === 80 ? '' : ':' + p.port}/`;
  if (p.service === 'ftp') return `ftp://${ip}/`;
  return '';
}

// The port a service normally runs on. A chip only shows the port when it is
// another one, so "https" and "https:8443" stay short and easy to tell apart.
const STD_PORT = {
  ftp: 21, ssh: 22, telnet: 23, smtp: 25, dns: 53, http: 80, kerberos: 88, pop3: 110,
  msrpc: 135, netbios: 139, imap: 143, ldap: 389, https: 443, smb: 445, lpd: 515,
  afp: 548, rtsp: 554, ipp: 631, ldaps: 636, imaps: 993, pop3s: 995, mssql: 1433,
  mqtt: 1883, nfs: 2049, mysql: 3306, rdp: 3389, postgres: 5432, vnc: 5900,
  winrm: 5985, 'winrm-tls': 5986, proxmox: 8006, jetdirect: 9100,
};

function chip(ip, p) {
  const label = !p.service ? String(p.port)
    : p.service + (STD_PORT[p.service] === p.port ? '' : ':' + p.port);
  const href = link(ip, p);
  const title = esc(`${p.port}/tcp ${p.service}${p.info ? ' — ' + p.info : ''}`);
  return href
    ? `<a class="chip" href="${esc(href)}" target="_blank" rel="noopener" title="${title}">${esc(label)}</a>`
    : `<span class="chip" title="${title}">${esc(label)}</span>`;
}

// Web interfaces first, as links, then everything else in port order.
function chips(h) {
  const web = h.ports.filter((p) => link(h.ip, p) && p.service !== 'ftp');
  const rest = h.ports.filter((p) => !web.includes(p));
  return web.concat(rest).map((p) => chip(h.ip, p)).join('');
}

function detail(h) {
  const svc = h.ports.length
    ? '<ul class="svc-list">' + h.ports.map((p) =>
      `<li><b>${p.port}/tcp ${esc(p.service)}</b> ${esc(p.info) || '<span class="muted">-</span>'}</li>`).join('') + '</ul>'
    : '<span class="muted">no open ports among those checked</span>';
  const rows = [
    ['Found by', esc(foundBy(h)) || '-'],
    ['Name', h.name ? `${esc(h.name)} <span class="muted small">(${h.name_src === 'netbios' ? 'NetBIOS' : 'reverse DNS'})</span>` : '<span class="muted">no name found</span>'],
    h.workgroup ? ['Workgroup / domain', esc(h.workgroup)] : null,
    h.moved_from ? ['Previous address', esc(h.moved_from)] : null,
    ['First seen', esc(when(h.first_seen)) || '-'],
    ['Services', svc],
  ].filter(Boolean);
  return `<tr class="detail"><td colspan="8"><dl>${rows.map(([a, b]) => `<dt>${a}</dt><dd>${b}</dd>`).join('')}</dl></td></tr>`;
}

/* ---------- CSV of what is shown ---------- */
function exportCsv() {
  const sc = S.view && S.view.scan;
  if (!sc) return;
  const q = (s) => {
    s = String(s == null ? '' : s);
    return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const head = ['status', 'ip', 'name', 'mac', 'vendor', 'ping_ms', 'found_by', 'open_ports', 'services', 'workgroup', 'first_seen'];
  const lines = [head.join(',')];
  for (const h of visible()) {
    lines.push([
      h.change || '', h.ip, h.name, h.mac, h.vendor, h.rtt == null ? '' : h.rtt.toFixed(2), h.via,
      h.ports.map((p) => p.port).join(' '),
      h.ports.map((p) => `${p.port}/${p.service}${p.info ? ' ' + p.info : ''}`).join('; '),
      h.workgroup, h.first_seen ? new Date(h.first_seen * 1000).toISOString().slice(0, 16).replace('T', ' ') : '',
    ].map(q).join(','));
  }
  // The BOM makes Excel read the file as UTF-8.
  const blob = new Blob(['﻿' + lines.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  const stamp = new Date(sc.started * 1000).toISOString().slice(0, 16).replace(/[-:]/g, '').replace('T', '-');
  a.href = URL.createObjectURL(blob);
  a.download = `webscan-${sc.id}-${stamp}${S.filter !== 'all' ? '-' + S.filter : ''}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* ---------- settings and access ---------- */
async function guard() {
  if (S.authed) return true;
  openSettings();
  return false;
}

function openSettings() {
  const locked = S.protected && !S.authed;
  $('login-box').classList.toggle('hidden', !locked);
  $('settings-body').classList.toggle('hidden', locked);
  $('logout').classList.toggle('hidden', !(S.protected && S.authed));
  $('cur-wrap').classList.toggle('hidden', !S.protected);
  const c = S.cfg;
  $('c-targets').value = c.default_targets || '';
  $('c-ports').value = (c.ports || []).join(', ');
  $('c-disc').value = (c.discovery_ports || []).join(', ');
  $('c-dns').value = (c.dns_servers || []).join(', ');
  $('c-ptime').value = c.ping_timeout; $('c-prounds').value = c.ping_rounds;
  $('c-arp').value = c.arp_wait_seconds; $('c-ctime').value = c.connect_timeout;
  $('c-threads').value = c.threads; $('c-max').value = c.max_hosts;
  $('c-sched').value = c.schedule_minutes; $('c-keep').value = c.keep_scans;
  $('c-names').checked = !!c.resolve_names; $('c-nb').checked = !!c.netbios; $('c-http').checked = !!c.http_titles;
  $('cfg-msg').textContent = ''; $('pw-msg').textContent = '';
  if (!$('dlg-settings').open) $('dlg-settings').showModal();
}

async function refreshSession() {
  const s = await api('/api/session');
  S.authed = s.authed; S.protected = s.protected;
}

/* ---------- wiring ---------- */
function init() {
  $('scan-form').onsubmit = async (e) => {
    e.preventDefault();
    if (!await guard()) return;
    $('scan-err').classList.add('hidden');
    try {
      const r = await post('/api/scan/start', { targets: $('targets').value.trim() });
      S.job = { id: r.id, targets: $('targets').value.trim(), phase: 'starting', done: 0, total: 0, started: Date.now() / 1000 };
      renderProgress();
    } catch (err) {
      $('scan-err').textContent = err.message; $('scan-err').classList.remove('hidden');
    }
  };
  $('btn-stop').onclick = async () => {
    if (!await guard()) return;
    try { await post('/api/scan/stop'); } catch (e) { alert(e.message); }
  };

  $('search').oninput = () => { S.query = $('search').value; render(); };
  for (const b of $('filters').children) b.onclick = () => { S.filter = b.dataset.f; render(); };
  for (const th of document.querySelectorAll('.hosts th')) {
    th.onclick = () => {
      const k = th.dataset.k;
      S.sort = { k, desc: S.sort.k === k ? !S.sort.desc : false };
      render();
    };
  }
  $('rows').onclick = (e) => {
    if (e.target.closest('a')) return;
    const tr = e.target.closest('tr.host');
    if (!tr) return;
    const id = tr.dataset.id;
    if (S.open.has(id)) S.open.delete(id); else S.open.add(id);
    render();
  };
  $('vs').onchange = () => { S.vs = +$('vs').value; loadScan(); };
  $('csv').onclick = exportCsv;

  $('btn-settings').onclick = openSettings;
  $('close-settings').onclick = () => $('dlg-settings').close();
  $('logout').onclick = async () => { await post('/api/logout'); await refreshSession(); openSettings(); };

  $('login-box').onsubmit = async (e) => {
    e.preventDefault();
    try {
      await post('/api/login', { password: $('pw').value });
      $('pw').value = ''; $('login-err').classList.add('hidden');
      await refreshSession(); openSettings();
    } catch (err) {
      $('login-err').textContent = err.message; $('login-err').classList.remove('hidden');
    }
  };

  $('cfg-form').onsubmit = async (e) => {
    e.preventDefault();
    const cfg = {
      default_targets: $('c-targets').value.trim(),
      ports: $('c-ports').value, discovery_ports: $('c-disc').value, dns_servers: $('c-dns').value,
      ping_timeout: +$('c-ptime').value, ping_rounds: +$('c-prounds').value,
      arp_wait_seconds: +$('c-arp').value, connect_timeout: +$('c-ctime').value,
      threads: +$('c-threads').value, max_hosts: +$('c-max').value,
      schedule_minutes: +$('c-sched').value, keep_scans: +$('c-keep').value,
      resolve_names: $('c-names').checked, netbios: $('c-nb').checked, http_titles: $('c-http').checked,
    };
    try {
      const r = await post('/api/config', cfg);
      S.cfg = r.config; openSettings(); $('cfg-msg').textContent = 'Saved.';
    } catch (err) { $('cfg-msg').textContent = err.message; }
  };

  $('pw-form').onsubmit = async (e) => {
    e.preventDefault();
    try {
      await post('/api/set-password', { current: $('pw-cur').value, new: $('pw-new').value });
      $('pw-cur').value = ''; $('pw-new').value = '';
      await refreshSession(); openSettings(); $('pw-msg').textContent = 'Password updated.';
    } catch (err) { $('pw-msg').textContent = err.message; }
  };

  tick();
}

init();
