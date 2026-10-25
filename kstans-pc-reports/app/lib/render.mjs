// Fills the page templates. The browser does the drawing (templates\*.html carry the scripts); the
// server only embeds the data. Flags here follow the same rules and keys as the PC page's own script,
// so the master page's counts match what each PC page shows.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const T = join(dirname(fileURLToPath(import.meta.url)), '..', 'templates');
const pcTemplate = readFileSync(join(T, 'pc.html'), 'utf8');
const indexTemplate = readFileSync(join(T, 'index.html'), 'utf8');
const loginTemplate = readFileSync(join(T, 'login.html'), 'utf8');
const printTemplate = readFileSync(join(T, 'print.html'), 'utf8');
// Shared by the PC page and the print page; served as static files.
export const assets = {
  '/report.js': { type: 'text/javascript; charset=utf-8', body: readFileSync(join(T, 'report.js'), 'utf8') },
  '/report.css': { type: 'text/css; charset=utf-8', body: readFileSync(join(T, 'report.css'), 'utf8') },
};

// GoTo alone would also catch GoToMeeting and GoTo Opener, which are not remote control.
const RAT = /AnyDesk|TeamViewer|ScreenConnect|ConnectWise|Splashtop|RustDesk|LogMeIn|GoTo Resolve|GoToAssist|RemotePC|Supremo|UltraViewer|AeroAdmin|Chrome Remote Desktop|Atera|NinjaRMM|Zoho Assist|MeshAgent|TruGrid/i;

// Keep "</script>" inside embedded data from closing the tag early.
const embed = (s) => s.replace(/<\//g, '<\\/');
const jsStr = (s) => embed(String(s ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'"));
const when = (s) => new Date(String(s).slice(0, 16).replace(' ', 'T'));
const uniq = (xs) => [...new Map(xs.map((x) => [x.toLowerCase(), x])).values()];

// Drives with no size (empty card readers, unmapped letters) come through with FreePercent {}.
const disksOf = (r) => (r.Disks || []).filter((d) => d && typeof d.SizeGB === 'number' && d.SizeGB > 0);

// Newest Windows update installed: the newest of Get-HotFix's list (Hotfixes) and Windows Update's own
// history (UpdateHistory, KB-numbered entries only, so driver updates don't count). Get-HotFix comes
// back empty on some fully patched PCs. Returns { id, on } or null.
export function newestUpdate(r) {
  const c = [];
  for (const h of r.Hotfixes || []) if (h?.InstalledOn) c.push({ id: h.ID, on: h.InstalledOn });
  for (const u of r.UpdateHistory || []) {
    const kb = String(u?.Title || '').match(/KB\d{6,8}/);
    if (kb && u.InstalledOn) c.push({ id: kb[0], on: u.InstalledOn });
  }
  return c.sort((a, b) => b.on.localeCompare(a.on))[0] || null;
}

// Each flag is { s: severity, t: chip text, k: key }. The key is what an "OK" mark is stored under,
// so it must not change between scans.
export function getFlags(r) {
  const f = [];
  const latest = newestUpdate(r);
  if (!latest) f.push({ s: 'bad', t: 'No updates listed', k: 'updates' });
  else {
    const age = Math.round((when(r.Collected) - when(latest.on)) / 864e5);
    if (age > 45) f.push({ s: 'bad', t: `No updates ${age} d`, k: 'updates' });
  }
  if (r.OS?.UptimeDays > 30) f.push({ s: 'warn', t: `Up ${Math.floor(r.OS.UptimeDays)} d`, k: 'uptime' });
  for (const d of disksOf(r)) if (d.FreePercent < 15) f.push({ s: d.FreePercent < 8 ? 'bad' : 'warn', t: `${d.Drive} ${d.FreePercent}% free`, k: `disk:${d.Drive}` });
  const M = r.MemoryGB || {};
  if (M.Total && M.Used / M.Total >= 0.85) f.push({ s: 'warn', t: `RAM ${Math.round((100 * M.Used) / M.Total)}%`, k: 'ram' });
  const scRaw = r.Antivirus?.SecurityCenter;
  const sc = Array.isArray(scRaw) ? scRaw.filter((a) => a && typeof a === 'object') : [];
  // Windows turns Defender off when another antivirus is active; only flag "off" when nothing runs.
  const live = sc.filter((a) => a.RealTime === 'Enabled');
  // Windows Server has no Security Center list; go by Defender's own status there.
  const md = r.Antivirus?.Defender;
  if (typeof scRaw === 'string' && md && !(md.AntivirusEnabled && md.RealTimeProtection)) f.push({ s: 'bad', t: 'Defender real-time off', k: 'defender-off' });
  if (sc.length && !live.length) f.push({ s: 'bad', t: 'No antivirus running', k: 'no-av' });
  for (const n of uniq(live.filter((a) => a.Definitions !== 'Up to date').map((a) => a.Name))) f.push({ s: 'bad', t: `${n} out of date`, k: `av-old:${n.toLowerCase()}` });
  if (live.length) for (const n of uniq(sc.filter((a) => a.RealTime !== 'Enabled' && !/Defender/i.test(a.Name)).map((a) => a.Name))) f.push({ s: 'warn', t: `${n} off`, k: `av-off:${n.toLowerCase()}` });
  // Webroot can register the same product twice; count each name once.
  if (uniq(live.map((a) => a.Name)).length > 1) f.push({ s: 'warn', t: '2 AVs live', k: 'two-av' });
  // One flag per remote-access product (LogMeIn and "LogMeIn Client" are one).
  for (const p of uniq((r.Software || []).map((s) => (s?.Name || '').match(RAT)?.[0]).filter(Boolean)).sort()) f.push({ s: 'warn', t: `Remote: ${p}`, k: `remote:${p.toLowerCase()}` });
  if ((r.Errors || []).length) f.push({ s: 'warn', t: `${r.Errors.length} collection error(s)`, k: 'errors' });
  return f;
}

// One row per SimpleHelp machine for the master page. reports: Map id -> parsed pc-report JSON.
export function indexRows(machines, reports, acks) {
  return machines.map((m) => {
    const r = reports.get(String(m.machineID));
    let flags = [];
    if (r) {
      try { flags = getFlags(r).map((x) => ({ ...x, ok: !!acks[m.machineID]?.[x.k] })); }
      catch { flags = [{ s: 'warn', t: 'Report unreadable', k: 'unreadable', ok: false }]; }
    }
    const latest = r ? newestUpdate(r) : null;
    const c = r ? disksOf(r).find((d) => d.Drive === 'C:') : null;
    return {
      id: m.machineID, name: m.name, online: !!m.online, host: m.hostname,
      group: m.group || 'Ungrouped',
      user: (r && r.Computer?.UserName) || m.consoleUser,
      os: r ? `${(r.OS?.Name || '').replace(/^Microsoft /, '')} ${r.OS?.DisplayVersion || ''}`.trim() : m.os,
      lastSeen: m.lastRegistrationTime ? ymd(new Date(Number(m.lastRegistrationTime))) : '',
      report: !!r,
      collected: r ? String(r.Collected).slice(0, 16) : '',
      lastUpdate: latest ? latest.on.slice(0, 10) : '',
      uptime: r ? Math.floor(r.OS?.UptimeDays ?? 0) : null,
      cFree: c ? c.FreePercent : null,
      model: r ? `${r.Computer?.Manufacturer || ''} ${r.Computer?.Model || ''}`.trim() : '',
      flags,
    };
  });
}

const pad = (n) => String(n).padStart(2, '0');
function ymd(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
function built(d) {
  const h = d.getHours() % 12 || 12;
  return `${ymd(d)} ${h}:${pad(d.getMinutes())} ${d.getHours() < 12 ? 'AM' : 'PM'}`;
}

export function renderIndex(rows) {
  return indexTemplate.replace('__BUILT__', built(new Date())).replace('__DATA__', () => embed(JSON.stringify(rows)));
}

// json: the raw pc-report text. acks: this machine's OK marks { key: { at } }.
export function renderPc(json, { title, back, id, acks }) {
  return pcTemplate
    .replace("'__TITLE__'", () => `'${jsStr(title)}'`)
    .replace("'__BACK__'", () => `'${jsStr(back)}'`)
    .replace("'__ID__'", () => `'${jsStr(id)}'`)
    .replace('__ACKS__', () => embed(JSON.stringify(acks || {})))
    .replace('__DATA__', () => embed(json));
}

// A group or subgroup as one printable document. pcs: [{ title, group, online, acks, report }] where
// report is the parsed pc-report JSON; missing: names of machines in the group never scanned.
export function renderPrint({ title, pcs, missing }) {
  return printTemplate.replace('__DATA__', () => embed(JSON.stringify({ title, built: built(new Date()), pcs, missing })));
}

export function renderLogin({ error = '', next = '/', setup = false } = {}) {
  const esc = (v) => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return loginTemplate
    .replace('__ERROR__', error ? `<p class="err">${esc(error)}</p>` : '')
    .replace('__NEXT__', esc(next))
    .replace('__FORM__', setup ? 'hidden' : '')
    .replace('__SETUP__', setup ? '' : 'hidden');
}
