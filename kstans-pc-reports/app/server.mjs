// PC Reports: every SimpleHelp machine by group, a report page per PC, and buttons to rescan,
// refresh the machine list and mark warnings OK. Runs on the Umbrel (kstans-pc-reports) behind a
// password; HTTPS comes from Tailscale Serve on the Umbrel.
//
// A rescan runs the read-only SimpleHelp toolbox tool "pc-report" (or "pc-report-legacy" on Windows too old
// for it) and nothing else. In the background
// the server re-reads the machine list every 15 minutes and scans PCs that have never been scanned.
// Auto fix AV (lib/fixav.mjs) is the exception: in the groups named by AUTO_FIX_AV_GROUPS it runs the
// antivirus removal tools and defender-on on PCs as they come online.
// The PC page's History and Notes tabs read SimpleHelp's session history and read/write the machine's
// SimpleHelp notes (the API token needs those permissions).
//
// Environment (set in the Umbrel app settings, never in this repo):
//   PC_REPORTS_PASSWORD   sign-in password
//   SIMPLEHELP_URL, SIMPLEHELP_TOKEN, SIMPLEHELP_TECHNICIAN, SIMPLEHELP_CONNECT_ADDRESS
//   DATA_DIR (default /data), PORT (default 8765)
//   AUTO_FIX_AV_GROUPS    comma-separated top-level groups for auto fix AV; empty = off
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, readdir, appendFile } from 'node:fs/promises';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { loadConfig, SimpleHelpClient } from './lib/simplehelp.mjs';
import { indexRows, renderIndex, renderPc, renderPrint, renderLogin, assets } from './lib/render.mjs';
import { createFixAv } from './lib/fixav.mjs';

const DATA = process.env.DATA_DIR || '/data';
const PORT = Number(process.env.PORT || 8765);
const PASSWORD = process.env.PC_REPORTS_PASSWORD || '';
// The only tools this app will ever run, both read-only. pc-report-legacy is the PowerShell 2.0 version
// for Windows 7 / Server 2008 R2 and older, where pc-report can't load.
const TOOL_NAME = 'pc-report', LEGACY_TOOL = 'pc-report-legacy';
const RUN_TIMEOUT_MS = 8 * 60 * 1000;
const ID = /^SG_-?\d+$/;

await mkdir(DATA, { recursive: true });
const config = loadConfig();
const client = new SimpleHelpClient(config);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const file = (name) => join(DATA, name);
const readJson = async (name, fallback) => (existsSync(file(name)) ? JSON.parse((await readFile(file(name), 'utf8')).replace(/^﻿/, '') || 'null') ?? fallback : fallback);

// ---- Sign-in -------------------------------------------------------------------------------
// A session is "<expiry ms>.<HMAC>" in an HttpOnly cookie. The HMAC key mixes a secret kept in the
// data folder with the password, so changing the password signs everyone out.
const SECRET_FILE = file('.session-secret');
if (!existsSync(SECRET_FILE)) writeFileSync(SECRET_FILE, randomBytes(32).toString('hex'), { mode: 0o600 });
const KEY = readFileSync(SECRET_FILE, 'utf8').trim() + '|' + PASSWORD;
const SESSION_DAYS = 30;
const sign = (v) => createHmac('sha256', KEY).update(v).digest('hex');
const sha = (s) => createHash('sha256').update(String(s)).digest();
const failures = new Map();   // ip -> { n, until }

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p.length === 2));
}
function signedIn(req) {
  if (!PASSWORD) return false;
  const [exp, mac] = (cookies(req).pcr || '').split('.');
  if (!exp || !mac || Number(exp) < Date.now()) return false;
  const want = sign(exp);
  return mac.length === want.length && timingSafeEqual(Buffer.from(mac), Buffer.from(want));
}
function sessionCookie(req) {
  const exp = String(Date.now() + SESSION_DAYS * 864e5);
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `pcr=${exp}.${sign(exp)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`;
}
const safeNext = (n) => (typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') ? n : '/');

// ---- Data ----------------------------------------------------------------------------------
async function refreshMachines() {
  const list = (await client.listMachines()) || [];
  const machines = list.map((m) => ({
    machineID: m.machineID, name: m.name, online: m.online, hostname: m.hostname, os: m.os,
    group: (m.groups || []).join('/'), consoleUser: m.consoleUser, lastRegistrationTime: m.lastRegistrationTime,
  }));
  await writeFile(file('machines.json'), JSON.stringify(machines, null, 2), 'utf8');
  return new Map(machines.map((m) => [String(m.machineID), m]));
}

async function loadReports() {
  const reports = new Map();
  for (const n of await readdir(DATA)) {
    if (!/^SG_-?\d+\.json$/.test(n)) continue;
    try { reports.set(n.slice(0, -5), JSON.parse(await readFile(file(n), 'utf8'))); } catch { /* unreadable: no report */ }
  }
  return reports;
}

// ---- Jobs: rescan and refresh ---------------------------------------------------------------
// "job" is the one rescan or refresh started from a button (one at a time; the page shows it).
// "auto" is the background scan of new PCs; it has its own slot so it never blocks the buttons.
let job = null, auto = null;

// Runs pc-report on ids and hands each machine's output to onDone as soon as it finishes, so pages
// fill in during a long scan. Stops waiting when every machine is done, when nothing new has
// finished for STALL_MS (old or dropped PCs can sit "running" forever), or after RUN_TIMEOUT_MS.
// Output is re-read only when more machines have finished, at most every 20 s: it carries every
// finished machine's full report each time.
const STALL_MS = 3 * 60 * 1000;
async function runReport(toolID, ids, onDone, label, j) {
  const res = await client.runTool({ technician: config.technician, toolID, machineIDs: ids });
  const runID = typeof res === 'string' ? res : res?.runID;
  if (!runID) throw new Error('SimpleHelp returned no run ID');
  const start = Date.now();
  let lastProgress = start, lastFetch = 0, fetchedAt = -1, done = 0;
  for (;;) {
    const st = await client.runStatus(runID);
    const now = (st?.machines || []).filter((m) => m.complete).length;
    if (now > done) { done = now; lastProgress = Date.now(); }
    const finished = st?.complete || done >= ids.length;
    if (done > fetchedAt && (finished || Date.now() - lastFetch > 20000)) {
      fetchedAt = done; lastFetch = Date.now();
      for (const r of (await client.runOutput(runID))?.machines || []) await onDone(r);
    }
    j.step = `${label}: ${done} of ${ids.length} finished`;
    if (finished || Date.now() - lastProgress > STALL_MS || Date.now() - start > RUN_TIMEOUT_MS) break;
    await sleep(8000);
  }
  if (done > fetchedAt) for (const r of (await client.runOutput(runID))?.machines || []) await onDone(r);
}

async function rescan(ids, label, background = false) {
  const j = { id: Date.now(), label, state: 'running', step: 'checking machines', startedAt: new Date().toISOString(), results: [] };
  if (background) auto = j; else job = j;
  try {
    const machines = await refreshMachines();
    const tools = (await client.listTools(config.technician)) || [];
    const byName = (n) => tools.find((t) => t.name?.trim().toLowerCase() === n);
    const tool = byName(TOOL_NAME), legacy = byName(LEGACY_TOOL);
    if (!tool) throw new Error(`"${TOOL_NAME}" is not in ${config.technician}'s toolbox`);
    const known = ids.map((id) => machines.get(id)).filter(Boolean);
    const online = known.filter((m) => m.online);
    for (const m of known.filter((m) => !m.online)) j.results.push({ id: m.machineID, name: m.name, status: 'offline, skipped' });
    if (!online.length) throw new Error('none of these machines is online');
    // Old Windows goes straight to the legacy tool; anything that isn't Windows is skipped.
    const notWin = online.filter((m) => !/Windows/i.test(m.os || ''));
    for (const m of notWin) j.results.push({ id: m.machineID, name: m.name, status: 'not Windows, skipped' });
    const old = online.filter((m) => /Windows/i.test(m.os || '') && !canRun(m.os));
    const modern = online.filter((m) => canRun(m.os));
    if (old.length && !legacy) for (const m of old) j.results.push({ id: m.machineID, name: m.name, status: `too old for pc-report; add "${LEGACY_TOOL}" to the toolbox` });

    // Each finished machine is saved right away. A machine that finished with empty or broken
    // output gets one retry (that usually works); one that never finished is not retried, since it
    // would only stall again.
    const saved = new Set(), empty = new Set();
    const onDone = async (r) => {
      const id = String(r.machineID);
      if (saved.has(id)) return;
      const out = (r.stdout || '').trim();
      try { if (out.startsWith('{')) { JSON.parse(out); await writeFile(file(`${id}.json`), out, 'utf8'); saved.add(id); empty.delete(id); return; } } catch { /* not JSON */ }
      empty.add(id);
    };
    if (modern.length) await runReport(tool.toolID, modern.map((m) => m.machineID), onDone, 'pc-report running', j);
    if (old.length && legacy) await runReport(legacy.toolID, old.map((m) => m.machineID), onDone, 'pc-report-legacy running', j);
    const retry = [...empty];
    empty.clear();   // from here, "empty" means the retry finished empty too
    const isOld = (id) => old.some((m) => String(m.machineID) === id);
    const retryModern = retry.filter((id) => !isOld(id)), retryOld = retry.filter(isOld);
    if (retryModern.length) await runReport(tool.toolID, retryModern, onDone, `retrying ${retryModern.length} that came back empty`, j);
    if (retryOld.length) await runReport(legacy.toolID, retryOld, onDone, `retrying ${retryOld.length} old PC(s) that came back empty`, j);
    // Empty twice from pc-report: one try with the legacy tool (an old PowerShell the OS name hid).
    const last = [...empty].filter((id) => legacy && modern.some((m) => String(m.machineID) === id));
    if (last.length) { for (const id of last) empty.delete(id); await runReport(legacy.toolID, last, onDone, `trying pc-report-legacy on ${last.length}`, j); }
    for (const m of [...modern, ...(legacy ? old : [])]) {
      const id = String(m.machineID);
      const status = saved.has(id) ? 'updated'
        : empty.has(id) ? 'finished but gave no report, twice'
        : retry.includes(id) ? 'retry did not finish'
        : 'did not finish (old Windows, or it went offline)';
      j.results.push({ id: m.machineID, name: m.name, status });
    }
    j.state = 'done';
    j.step = `${j.results.filter((r) => r.status === 'updated').length} of ${ids.length} updated`;
  } catch (e) {
    j.state = 'failed';
    j.step = client.scrub(e.message);
  }
  j.finishedAt = new Date().toISOString();
  if (background) console.log(`auto-scan ${j.state}: ${j.step}`);
}

// Re-read groups, names and online status from SimpleHelp. Runs nothing on any PC.
async function refreshList() {
  job = { id: Date.now(), label: 'the machine list', state: 'running', step: 'reading SimpleHelp machine list', startedAt: new Date().toISOString(), results: [] };
  try {
    const machines = await refreshMachines();
    job.state = 'done';
    job.step = `${machines.size} machines, ${[...machines.values()].filter((m) => m.online).length} online`;
  } catch (e) {
    job.state = 'failed';
    job.step = client.scrub(e.message);
  }
  job.finishedAt = new Date().toISOString();
}

// ---- Background: keep the list fresh and scan new PCs ------------------------------------------
// Every AUTO_MS the machine list is re-read from SimpleHelp (one API call, nothing runs on a PC), and
// any online machine that has never had a report gets one scan. A machine is tried at most once a
// day (autoscan.json: { "<machineID>": <last try ms> }). Machines that aren't Windows are left out;
// Windows older than 8 / Server 2012 gets pc-report-legacy (see rescan). It runs alongside button
// jobs; only one background scan at a time.
const AUTO_MS = 15 * 60 * 1000;
// SimpleHelp's os text, e.g. "Windows 11 (25H2) Intel/64", "Windows 7 (7601) Intel/64", "Windows Server 2008 R2 ...".
const canRun = (os) => /Windows/i.test(os || '') && !/Windows (XP|Vista|7|8)\b(?!\.1)|Server 200[0-8]/i.test(os || '');
async function autoTick() {
  await scanNew();
  fixAv.tick();   // runs on its own; skips the pass if the last one is still going
}
async function scanNew() {
  if (config.missing.length || auto?.state === 'running') return;
  try {
    const machines = await refreshMachines();
    const scanned = new Set((await readdir(DATA)).filter((n) => /^SG_-?\d+\.json$/.test(n)).map((n) => n.slice(0, -5)));
    const tried = await readJson('autoscan.json', {});
    const fresh = [...machines.values()].filter((m) => m.online && /Windows/i.test(m.os || '') && !scanned.has(String(m.machineID)) && !(Date.now() - (tried[m.machineID] || 0) < 864e5));
    if (!fresh.length) return;
    for (const m of fresh) tried[m.machineID] = Date.now();
    await writeFile(file('autoscan.json'), JSON.stringify(tried, null, 2), 'utf8');
    const names = fresh.map((m) => m.name).join(', ');
    console.log(`auto-scan: ${fresh.length} never-scanned PC(s) online: ${names}`);
    await rescan(fresh.map((m) => String(m.machineID)), `new PC${fresh.length === 1 ? '' : 's'}: ${names}`.slice(0, 120), true);
  } catch (e) {
    console.log(`auto-scan pass failed: ${client.scrub(e.message)}`);
  }
}
const fixAv = createFixAv({ client, config, file, canRun });
setTimeout(autoTick, 60 * 1000);
setInterval(autoTick, AUTO_MS);

// ---- History tab: SimpleHelp's session history for one PC ----------------------------------------
// SimpleHelp lists remote sessions with their type and mode, but toolbox runs come back with no type
// or tool name. So every tool run is also written to toolruns.jsonl ({ at, id, tool, result? }): runs
// this app starts (logged here) and runs started from the Chief of Staff hub (appended by its pc-job
// script). A SimpleHelp tool session takes the name of the logged run that started within 3 minutes
// of it. Fix AV log entries for the PC are added as their own rows.
const RUNLOG = 'toolruns.jsonl', MATCH_MS = 3 * 60 * 1000, HISTORY_DAYS = 180;
const toolNames = new Map();
const listTools = client.listTools.bind(client), runTool = client.runTool.bind(client);
client.listTools = async (...a) => { const t = await listTools(...a); for (const x of t || []) toolNames.set(x.toolID, x.name); return t; };
client.runTool = async (args) => {
  const at = Date.now(), res = await runTool(args);
  const lines = (args.machineIDs || []).map((id) => JSON.stringify({ at, id: String(id), tool: toolNames.get(args.toolID) || 'toolbox tool' }) + '\n');
  await appendFile(file(RUNLOG), lines.join(''), 'utf8').catch(() => {});
  return res;
};
async function pcHistory(id) {
  const since = Date.now() - HISTORY_DAYS * 864e5;
  let runs = [];
  try { runs = (await readFile(file(RUNLOG), 'utf8')).split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((r) => r && r.id === id && r.at >= since); } catch { /* no log yet */ }
  const sessions = await client.history(id, since);
  const used = new Set();
  const rows = sessions.map((s) => {
    const row = { at: s.start, minutes: Math.round((s.duration || 0) / 6e4), tech: s.technicianName || s.technicianUsername || '',
      what: s.type ? `${s.type}${s.mode ? ` (${s.mode})` : ''}` : 'Toolbox run', events: s.sessionEvents || [] };
    if (!s.type) {
      const near = runs.filter((r) => !used.has(r) && Math.abs(r.at - s.start) < MATCH_MS).sort((a, b) => Math.abs(a.at - s.start) - Math.abs(b.at - s.start))[0];
      if (near) { used.add(near); row.what = `Tool: ${near.tool}`; if (near.result) row.result = near.result; }
    }
    return row;
  });
  // Logged runs SimpleHelp didn't list (or listed past maxResults) still show.
  for (const r of runs.filter((r) => !used.has(r))) rows.push({ at: r.at, what: `Tool: ${r.tool}`, result: r.result, tech: '', events: [] });
  for (const e of (await readJson('fixav-log.json', [])).filter((e) => String(e.id) === id)) {
    rows.push({ at: Date.parse(e.at), what: 'Auto fix AV', result: `${e.why || ''}: ${(e.steps || []).map((s) => `${s.tool} ${s.result}`).join('; ')}`, tech: 'PC Reports', events: [] });
  }
  return rows.sort((a, b) => b.at - a.at);
}

// ---- Mark OK: acks.json is { "<machineID>": { "<flag key>": { "at": "<date>" } } } -----------
let ackChain = Promise.resolve();
async function setAck(id, key, ok) {
  const acks = await readJson('acks.json', {});
  if (ok) (acks[id] ??= {})[key] = { at: new Date().toISOString() };
  else if (acks[id]) { delete acks[id][key]; if (!Object.keys(acks[id]).length) delete acks[id]; }
  await writeFile(file('acks.json'), JSON.stringify(acks, null, 2), 'utf8');
}

// ---- HTTP ----------------------------------------------------------------------------------
const html = (res, code, body, extra = {}) => res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...extra }).end(body);
const json = (res, code, body) => res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(body));
async function body(req, limit) {
  let b = '';
  for await (const c of req) { b += c; if (b.length > limit) throw Object.assign(new Error('too large'), { code: 413 }); }
  return b;
}

createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname;
    const ip = req.socket.remoteAddress;

    if (path === '/login' && req.method === 'GET') {
      if (signedIn(req)) return html(res, 302, '', { Location: safeNext(url.searchParams.get('next')) });
      return html(res, 200, renderLogin({ next: safeNext(url.searchParams.get('next')), setup: !PASSWORD }));
    }
    if (path === '/login' && req.method === 'POST') {
      const form = new URLSearchParams(await body(req, 4000));
      const next = safeNext(form.get('next'));
      const f = failures.get(ip) || { n: 0, until: 0 };
      if (Date.now() < f.until) return html(res, 429, renderLogin({ next, error: 'Too many tries. Wait a minute and try again.' }));
      if (PASSWORD && timingSafeEqual(sha(form.get('password') || ''), sha(PASSWORD))) {
        failures.delete(ip);
        return html(res, 303, '', { Location: next, 'Set-Cookie': sessionCookie(req) });
      }
      f.n += 1;
      if (f.n >= 5) { f.until = Date.now() + 60000; f.n = 0; }
      failures.set(ip, f);
      return html(res, 401, renderLogin({ next, error: 'Wrong password.', setup: !PASSWORD }));
    }
    if (path === '/logout') return html(res, 303, '', { Location: '/login', 'Set-Cookie': 'pcr=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' });

    if (!signedIn(req)) {
      if (path.startsWith('/api/')) return json(res, 401, { error: 'Signed out. Reload the page to sign in again.' });
      return html(res, 302, '', { Location: `/login?next=${encodeURIComponent(path)}` });
    }

    // Write calls must send JSON, which a form on another site cannot do without permission.
    if (req.method === 'POST' && !(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'JSON only' });
    if (config.missing.length && path.startsWith('/api/') && path !== '/api/ping' && path !== '/api/job') {
      return json(res, 503, { error: `SimpleHelp settings missing: ${config.missing.join(', ')}. Set them in the Umbrel app settings.` });
    }

    if (path === '/api/ping') return json(res, 200, { ok: true });
    if (path === '/api/job') return json(res, 200, job || { state: 'idle' });
    if (path === '/api/rescan' && req.method === 'POST') {
      if (job?.state === 'running') return json(res, 409, { error: `A rescan is already running: ${job.label}` });
      const { ids, label } = JSON.parse(await body(req, 100000) || '{}');
      if (!Array.isArray(ids) || !ids.length || ids.length > 400 || !ids.every((x) => ID.test(String(x)))) return json(res, 400, { error: 'ids must be 1-400 SimpleHelp machine IDs' });
      rescan(ids.map(String), String(label || `${ids.length} machine(s)`).slice(0, 120));
      return json(res, 202, { started: true, id: job.id });
    }
    if (path === '/api/refresh' && req.method === 'POST') {
      if (job?.state === 'running') return json(res, 409, { error: `Busy: ${job.label}` });
      refreshList();
      return json(res, 202, { started: true, id: job.id });
    }
    if (path === '/api/ack' && req.method === 'POST') {
      const { id, key, ok } = JSON.parse(await body(req, 10000) || '{}');
      if (!ID.test(String(id)) || !/^[\w:. ()-]{1,100}$/.test(String(key))) return json(res, 400, { error: 'bad id or key' });
      const p = ackChain.then(() => setAck(String(id), String(key), ok !== false));
      ackChain = p.catch(() => {});
      await p;
      return json(res, 200, { ok: true });
    }
    // PC page tabs: SimpleHelp history and the machine's SimpleHelp notes.
    if (path === '/api/history' && ID.test(url.searchParams.get('id') || '')) return json(res, 200, { rows: await pcHistory(url.searchParams.get('id')) });
    if (path === '/api/notes' && req.method === 'GET' && ID.test(url.searchParams.get('id') || '')) {
      const n = await client.getNotes(url.searchParams.get('id'));
      return json(res, 200, { notes: n?.notes || '' });
    }
    if (path === '/api/notes' && req.method === 'POST') {
      const { id, notes } = JSON.parse(await body(req, 40000) || '{}');
      if (!ID.test(String(id)) || typeof notes !== 'string' || notes.length > 20000) return json(res, 400, { error: 'bad id or notes' });
      await client.setNotes(String(id), notes);
      return json(res, 200, { notes: (await client.getNotes(String(id)))?.notes || '' });
    }

    if (path === '/' || path === '/index.html') {
      const machines = await readJson('machines.json', []);
      return html(res, 200, renderIndex(indexRows(machines, await loadReports(), await readJson('acks.json', {}))));
    }
    if (path === '/fixav') return html(res, 200, await fixAv.page());
    if (assets[path]) return res.writeHead(200, { 'Content-Type': assets[path].type, 'Cache-Control': 'no-cache' }).end(assets[path].body);
    // One printable document for a group (and its subgroups) or, with exact=1, one subgroup:
    // every machine in it that has a report, online or not.
    if (path === '/print') {
      const g = url.searchParams.get('group') || '', exact = url.searchParams.get('exact') === '1';
      if (!g) return html(res, 400, 'group is required');
      const inGroup = (m) => { const mg = m.group || 'Ungrouped'; return mg === g || (!exact && mg.startsWith(g + '/')); };
      const ms = (await readJson('machines.json', [])).filter(inGroup)
        .sort((a, b) => (a.group || '').localeCompare(b.group || '') || String(a.name).localeCompare(String(b.name)));
      const acks = await readJson('acks.json', {}), pcs = [], missing = [];
      for (const m of ms) {
        const id = String(m.machineID);
        let report = null;
        try { if (existsSync(file(`${id}.json`))) report = JSON.parse(await readFile(file(`${id}.json`), 'utf8')); } catch { /* unreadable: treated as never scanned */ }
        if (report) pcs.push({ title: m.name, group: m.group || 'Ungrouped', online: !!m.online, acks: acks[id] || {}, report });
        else missing.push(m.name);
      }
      return html(res, 200, renderPrint({ title: g, pcs, missing }));
    }
    const pc = path.match(/^\/pc\/(SG_-?\d+)\.html$/);
    if (pc && existsSync(file(`${pc[1]}.json`))) {
      const id = pc[1];
      const name = (await readJson('machines.json', [])).find((m) => String(m.machineID) === id)?.name || id;
      const acks = (await readJson('acks.json', {}))[id] || {};
      return html(res, 200, renderPc(await readFile(file(`${id}.json`), 'utf8'), { title: name, back: '../index.html', id, acks }));
    }
    return html(res, 404, 'Not found');
  } catch (e) {
    if (e.code === 413) return json(res, 413, { error: 'too large' });
    return json(res, 500, { error: client.scrub(e.message) });
  }
}).listen(PORT, process.env.HOST || '0.0.0.0', () => {
  console.log(`PC Reports on port ${PORT}; data in ${DATA}` + (PASSWORD ? '' : '; PC_REPORTS_PASSWORD is not set, sign-in is disabled') +
    (config.missing.length ? `; SimpleHelp settings missing: ${config.missing.join(', ')}` : ''));
});
