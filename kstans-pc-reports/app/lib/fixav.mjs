// Auto fix AV (Keith, 2026-10-27): on online Windows workstations in the groups named by
// AUTO_FIX_AV_GROUPS, remove every antivirus except Microsoft Defender, then turn Defender on and update
// it. The PC's saved report says what is there (rescanned first if over a day old); the removal tools
// are SimpleHelp toolbox tools. Never restarts a PC. Each PC is looked at once a day (fixav-state.json);
// everything done is logged to fixav-log.json and shown at /fixav.
//
// This is the only part of the app that runs anything but the read-only report tools, and only the
// tools in FIX_TOOLS. Leave AUTO_FIX_AV_GROUPS empty to turn it off.
import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { getFlags } from './render.mjs';

export const FIX_TOOLS = ['remove-webroot-force', 'remove-kaspersky-v4', 'clear-stale-av', 'defender-on'];
const DAY = 864e5, LOG_MAX = 300;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (v) => String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// What fix av needs on one PC: removal tools for the products found, products with no tool, and
// whether to act at all (another antivirus registered, or Defender off or out of date).
export function planFix(r) {
  const sc = (r.Antivirus?.SecurityCenter || []).filter((a) => a && typeof a === 'object').map((a) => String(a.Name || ''))
    .filter((n) => n && !/Windows Defender|Microsoft Defender/i.test(n));
  const sw = (r.Software || []).map((s) => String(s?.Name || ''));
  const has = (re) => sc.some((n) => re.test(n)) || sw.some((n) => re.test(n));
  const tools = [];
  if (has(/Webroot|OpenText/i)) tools.push('remove-webroot-force');
  if (has(/Kaspersky/i)) tools.push('remove-kaspersky-v4');
  const noTool = [...new Set(sc.filter((n) => !/Webroot|OpenText|Kaspersky/i.test(n)))];
  const d = r.Antivirus?.Defender;
  const defenderBad = !d || !d.AntivirusEnabled || !d.RealTimeProtection || (d.SignatureAgeDays ?? 999) > 3;
  return {
    act: !!(tools.length || sc.length || defenderBad), tools, noTool,
    why: [...new Set(sc)].join('; ') || (defenderBad ? 'Defender off or out of date' : ''),
  };
}

export function createFixAv({ client, config, file, canRun }) {
  const groups = (process.env.AUTO_FIX_AV_GROUPS || '').split(',').map((g) => g.trim()).filter(Boolean);
  let busy = null;   // { name, step } while a PC is being fixed
  const readJson = async (n, fb) => { try { return existsSync(file(n)) ? JSON.parse(await readFile(file(n), 'utf8')) : fb; } catch { return fb; } };
  const report = async (id) => readJson(`${id}.json`, null);

  // Runs one toolbox tool on one PC and waits for it (up to maxMs). Returns { code, out }.
  async function runOne(toolID, id, maxMs) {
    const res = await client.runTool({ technician: config.technician, toolID, machineIDs: [id] });
    const runID = typeof res === 'string' ? res : res?.runID;
    if (!runID) throw new Error('SimpleHelp returned no run ID');
    const end = Date.now() + maxMs;
    for (;;) {
      await sleep(15000);
      const st = await client.runStatus(runID).catch(() => null);
      if (st?.complete || (st?.machines || []).some((m) => m.complete) || Date.now() > end) break;
    }
    const m = ((await client.runOutput(runID).catch(() => null))?.machines || [])[0] || {};
    return { code: m.returnCode ?? null, out: String(m.stdout || '').trim() };
  }

  async function fixOne(m, tools) {
    const id = String(m.machineID);
    const entry = { at: new Date().toISOString(), id, name: m.name, steps: [] };
    const tool = (n) => tools.find((t) => t.name?.trim().toLowerCase() === n);
    const scan = async () => {
      const t = tool('pc-report');
      if (!t) return null;
      const { out } = await runOne(t.toolID, id, 10 * 60e3);
      try { if (out.startsWith('{')) { JSON.parse(out); await writeFile(file(`${id}.json`), out, 'utf8'); } } catch { /* not a report */ }
      return report(id);
    };
    let r = await report(id);
    if (!r || Date.now() - Date.parse(String(r.Collected).slice(0, 19)) > DAY) { busy.step = 'rescanning first'; r = (await scan()) || r; }
    if (!r) return { result: 'no report' };
    const p = planFix(r);
    if (!p.act) return { result: 'clean' };
    entry.why = p.why; entry.noTool = p.noTool;
    for (const n of [...p.tools, 'clear-stale-av', 'defender-on']) {
      const t = tool(n);
      busy.step = n;
      if (!t) { entry.steps.push({ tool: n, result: 'not in the SimpleHelp toolbox' }); continue; }
      try {
        const { code, out } = await runOne(t.toolID, id, (n === 'remove-kaspersky-v4' ? 35 : 10) * 60e3);
        entry.steps.push({ tool: n, code, result: out.split(/\r?\n/)[0] || '(no output)', detail: out.slice(0, 4000) });
      } catch (e) { entry.steps.push({ tool: n, result: client.scrub(e.message) }); }
    }
    busy.step = 'rescanning';
    const after = await scan();
    entry.flags = after ? getFlags(after).map((f) => f.t) : null;
    const log = await readJson('fixav-log.json', []);
    log.unshift(entry);
    await writeFile(file('fixav-log.json'), JSON.stringify(log.slice(0, LOG_MAX), null, 1), 'utf8');
    console.log(`fix av ${m.name}: ${entry.steps.map((s) => `${s.tool} -> ${s.result}`).join(' | ')}`);
    return { result: 'fixed', flags: entry.flags };
  }

  // Called by the server's background timer after the machine list is refreshed.
  async function tick() {
    if (!groups.length || busy || config.missing.length) return;
    busy = { name: '', step: 'checking' };
    try {
      const machines = await readJson('machines.json', []);
      const state = await readJson('fixav-state.json', {});
      const due = machines.filter((m) => m.online && groups.includes(String(m.group || '').split('/')[0]) &&
        canRun(m.os) && !/Server/i.test(m.os || '') && !(Date.now() - (state[m.machineID]?.at || 0) < DAY));
      if (!due.length) return;
      const tools = (await client.listTools(config.technician)) || [];
      for (const m of due) {
        busy.name = m.name;
        let res;
        try { res = await fixOne(m, tools); } catch (e) { res = { result: client.scrub(e.message) }; }
        state[m.machineID] = { at: Date.now(), ...res };
        await writeFile(file('fixav-state.json'), JSON.stringify(state, null, 1), 'utf8');
      }
    } catch (e) {
      console.log(`fix av pass failed: ${client.scrub(e.message)}`);
    } finally { busy = null; }
  }

  async function page() {
    const log = await readJson('fixav-log.json', []);
    const state = await readJson('fixav-state.json', {});
    const counts = Object.values(state).reduce((a, s) => ((a[s.result] = (a[s.result] || 0) + 1), a), {});
    const rows = log.map((e) => `<tr><td>${esc(new Date(e.at).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' }))}</td>
      <td><a href="/pc/${esc(e.id)}.html">${esc(e.name)}</a></td><td>${esc(e.why)}${e.noTool?.length ? `<div class="bad">no removal tool for: ${esc(e.noTool.join(', '))}</div>` : ''}</td>
      <td>${e.steps.map((s) => `<details><summary><b>${esc(s.tool)}</b> ${esc(s.result)}</summary><pre>${esc(s.detail || '')}</pre></details>`).join('')}</td>
      <td>${e.flags ? (e.flags.length ? e.flags.map((f) => `<span class="chip">${esc(f)}</span>`).join(' ') : '<span class="ok">clean</span>') : 'no rescan'}</td></tr>`).join('');
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fix AV log</title><style>
:root { --bg:#f6f7f9; --card:#fff; --ink:#1d2330; --muted:#6a7282; --line:#e3e6eb; --accent:#2563eb; --ok:#15803d; --bad:#b91c1c; --chip:#eef0f3; }
@media (prefers-color-scheme: dark) { :root { --bg:#12151b; --card:#1a1f27; --ink:#e6e9ef; --muted:#98a1b2; --line:#2a313c; --accent:#6ea0ff; --ok:#4ade80; --bad:#f87171; --chip:#252b35; } }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
.wrap { max-width:1240px; margin:0 auto; padding:28px 16px 48px; } a { color:var(--accent); }
h1 { margin:0 0 4px; font-size:26px; } .sub { color:var(--muted); margin-bottom:16px; }
.scroll { overflow-x:auto; } table { width:100%; border-collapse:collapse; background:var(--card); }
th, td { text-align:left; vertical-align:top; padding:8px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:12px; } pre { white-space:pre-wrap; font-size:12px; margin:4px 0; }
.chip { background:var(--chip); border-radius:10px; padding:1px 8px; font-size:12px; } .ok { color:var(--ok); } .bad { color:var(--bad); font-size:12px; }
</style></head><body><div class="wrap">
<a href="/">&larr; PC Report</a><h1>Fix AV log</h1>
<div class="sub">${groups.length ? `On for ${esc(groups.join(', '))}: removes every antivirus but Defender, then turns Defender on and updates it. Never restarts a PC. Each PC is checked once a day.` : 'Off (AUTO_FIX_AV_GROUPS is empty).'}
${busy ? `<br>Working on ${esc(busy.name)}: ${esc(busy.step)}` : ''}
<br>PCs checked so far: ${Object.entries(counts).map(([k, v]) => `${esc(k)} ${v}`).join(', ') || 'none yet'}</div>
${log.length ? `<div class="scroll"><table><tr><th>When</th><th>PC</th><th>Found</th><th>Steps</th><th>Flags after</th></tr>${rows}</table></div>` : '<p>Nothing fixed yet.</p>'}
</div></body></html>`;
  }

  return { tick, page, enabled: () => groups.length > 0 };
}
