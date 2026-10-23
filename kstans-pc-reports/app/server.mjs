// PC Reports: every SimpleHelp machine by group, a report page per PC, and buttons to rescan,
// refresh the machine list and mark warnings OK. Runs on the Umbrel (kstans-pc-reports) behind a
// password; HTTPS comes from Tailscale Serve on the Umbrel.
//
// A rescan runs the read-only SimpleHelp toolbox tool "pc-report" and nothing else.
//
// Environment (set in the Umbrel app settings, never in this repo):
//   PC_REPORTS_PASSWORD   sign-in password
//   SIMPLEHELP_URL, SIMPLEHELP_TOKEN, SIMPLEHELP_TECHNICIAN, SIMPLEHELP_CONNECT_ADDRESS
//   DATA_DIR (default /data), PORT (default 8765)
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { loadConfig, SimpleHelpClient } from './lib/simplehelp.mjs';
import { indexRows, renderIndex, renderPc, renderLogin } from './lib/render.mjs';

const DATA = process.env.DATA_DIR || '/data';
const PORT = Number(process.env.PORT || 8765);
const PASSWORD = process.env.PC_REPORTS_PASSWORD || '';
const TOOL_NAME = 'pc-report';   // the only tool this app will ever run
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

// ---- Jobs: rescan and refresh (one at a time) -----------------------------------------------
let job = null;

async function runReport(toolID, ids) {
  const res = await client.runTool({ technician: config.technician, toolID, machineIDs: ids });
  const runID = typeof res === 'string' ? res : res?.runID;
  if (!runID) throw new Error('SimpleHelp returned no run ID');
  const start = Date.now();
  for (;;) {
    const st = await client.runStatus(runID);
    job.step = `pc-report running: ${(st?.machines || []).filter((m) => m.complete).length} of ${ids.length} finished`;
    if (st?.complete || Date.now() - start > RUN_TIMEOUT_MS) break;
    await sleep(8000);
  }
  return (await client.runOutput(runID))?.machines || [];
}

async function rescan(ids, label) {
  job = { id: Date.now(), label, state: 'running', step: 'checking machines', startedAt: new Date().toISOString(), results: [] };
  try {
    const machines = await refreshMachines();
    const tool = ((await client.listTools(config.technician)) || []).find((t) => t.name?.trim().toLowerCase() === TOOL_NAME);
    if (!tool) throw new Error(`"${TOOL_NAME}" is not in ${config.technician}'s toolbox`);
    const known = ids.map((id) => machines.get(id)).filter(Boolean);
    const online = known.filter((m) => m.online);
    for (const m of known.filter((m) => !m.online)) job.results.push({ id: m.machineID, name: m.name, status: 'offline, skipped' });
    if (!online.length) throw new Error('none of these machines is online');

    // Runs sometimes come back with empty output for a machine; one retry usually works.
    let pending = online.map((m) => m.machineID);
    const got = new Map();
    for (let attempt = 1; attempt <= 2 && pending.length; attempt++) {
      if (attempt === 2) job.step = `retrying ${pending.length} that came back empty`;
      for (const r of await runReport(tool.toolID, pending)) {
        if (r.stdout && r.stdout.trim().startsWith('{')) got.set(String(r.machineID), r.stdout);
      }
      pending = pending.filter((id) => !got.has(String(id)));
    }
    for (const m of online) {
      const out = got.get(String(m.machineID));
      if (!out) { job.results.push({ id: m.machineID, name: m.name, status: 'no output (still pending or empty)' }); continue; }
      try { JSON.parse(out); } catch { job.results.push({ id: m.machineID, name: m.name, status: 'output was not valid JSON' }); continue; }
      await writeFile(file(`${m.machineID}.json`), out, 'utf8');
      job.results.push({ id: m.machineID, name: m.name, status: 'updated' });
    }
    job.state = 'done';
    job.step = `${job.results.filter((r) => r.status === 'updated').length} of ${ids.length} updated`;
  } catch (e) {
    job.state = 'failed';
    job.step = client.scrub(e.message);
  }
  job.finishedAt = new Date().toISOString();
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

    if (path === '/' || path === '/index.html') {
      const machines = await readJson('machines.json', []);
      return html(res, 200, renderIndex(indexRows(machines, await loadReports(), await readJson('acks.json', {}))));
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
