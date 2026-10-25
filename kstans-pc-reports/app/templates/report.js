// Draws one PC report from pc-report JSON. Shared by the PC page (pc.html) and the group print page
// (print.html), so a PDF shows exactly what the PC page shows. Served at /report.js.
//
// pcReport(d, { title, back, id, acks, print }) returns { html, software } where software is the
// sorted list the PC page's filter box draws from. With print: true there are no buttons, links or
// filter box, the whole software list is in the HTML and the services list is open.
(function () {
const esc = v => v == null ? '' : String(v).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const list = v => (Array.isArray(v) ? v : [v]).filter(x => x != null && x !== '');
const pct = (part, total) => total ? Math.round(part / total * 100) : 0;
const barColor = p => p >= 90 ? 'var(--bad)' : p >= 75 ? 'var(--warn)' : 'var(--ok)';
const kv = rows => '<table class="kv">' + rows.filter(r => r[1] !== undefined).map(([k, v]) =>
  `<tr><td>${esc(k)}</td><td>${v === null || v === '' ? '<span class="small">-</span>' : v}</td></tr>`).join('') + '</table>';
const table = (cols, rows) => '<table><thead><tr>' + cols.map(c => `<th>${esc(c)}</th>`).join('') +
  '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => `<td>${c ?? ''}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
const yesno = b => b ? '<span class="pill ok">Yes</span>' : '<span class="pill">No</span>';
// GoTo alone would also catch GoToMeeting and GoTo Opener, which are not remote control.
const rat = /AnyDesk|TeamViewer|ScreenConnect|ConnectWise|Splashtop|RustDesk|LogMeIn|GoTo Resolve|GoToAssist|RemotePC|Supremo|UltraViewer|AeroAdmin|Chrome Remote Desktop|Atera|NinjaRMM|Zoho Assist|MeshAgent|TruGrid/i;
const fmtDate = s => s && /^\d{8}$/.test(s) ? `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6)}` : esc(s);
const swRow = s => `<tr><td>${rat.test(s.Name || '') ? '<b>' + esc(s.Name) + '</b> <span class="pill bad">remote access</span>' : esc(s.Name)}</td>
    <td class="mono">${esc(s.Version)}</td><td>${esc(s.Publisher)}</td><td>${fmtDate(s.InstallDate)}</td><td><span class="pill">${esc(s.Scope)}</span></td></tr>`;

function pcReport(d, { title: TITLE = '', back: BACK = '', id: MID = '', acks: ACKS = {}, print = false } = {}) {
  const day = s => s ? new Date(s.replace(' ', 'T')) : null;
  const daysAgo = s => { const t = day(s); return t ? Math.floor((day(d.Collected.slice(0,16)) - t) / 864e5) : null; };
  const C = d.Computer || {}, B = d.Bios || {}, O = d.OS || {}, M = d.MemoryGB || {};
  const cpu = (d.CPU || [])[0] || {};
  // On Windows Server, SecurityCenter is a note string instead of a list.
  // Drives with no size (empty card readers, unmapped letters) come through with FreePercent {}.
  const disks = (d.Disks || []).filter(k => typeof k.SizeGB === 'number' && k.SizeGB > 0), nets = d.Network || [], av = d.Antivirus || {}, sc = Array.isArray(av.SecurityCenter) ? av.SecurityCenter : [];
  const scNote = typeof av.SecurityCenter === 'string' ? av.SecurityCenter : '';
  const def = av.Defender || {}, hot = (d.Hotfixes || []).slice().sort((a, b) => (b.InstalledOn || '').localeCompare(a.InstalledOn || ''));
  const sw = d.Software || [], svc = d.RunningServices || [], prn = d.Printers || [], errs = d.Errors || [];

  // Things worth a look, worst first. Each is [severity, title, detail, key]; the key is what an
  // "OK" mark is stored under, so it must stay the same from one scan to the next (same keys as
  // lib/render.mjs getFlags).
  const flags = [];
  // Newest of the hotfix list and Windows Update's own history (KB-numbered entries only), as in
  // lib/render.mjs newestUpdate: the hotfix list comes back empty on some fully patched PCs.
  const wuh = (d.UpdateHistory || []).filter(u => u && /KB\d{6,8}/.test(u.Title || '') && u.InstalledOn);
  const latest = [...hot.filter(h => h.InstalledOn).map(h => ({ id: h.ID, on: h.InstalledOn })),
    ...wuh.map(u => ({ id: u.Title.match(/KB\d{6,8}/)[0], on: u.InstalledOn }))].sort((a, b) => b.on.localeCompare(a.on))[0] || null;
  const lastPatch = latest ? daysAgo(latest.on) : null;
  if (lastPatch === null) flags.push(['bad', 'No Windows updates listed', 'Neither the hotfix list nor Windows Update history shows an installed update.', 'updates']);
  else if (lastPatch > 45) flags.push(['bad', `No Windows updates in ${lastPatch} days`, `Newest is ${esc(latest.id)}, installed ${esc(latest.on.slice(0,10))}.`, 'updates']);
  if (O.UptimeDays > 30) flags.push(['warn', `Not restarted in ${Math.floor(O.UptimeDays)} days`, `Last boot ${esc(O.LastBoot)}. Pending updates usually need a restart.`, 'uptime']);
  disks.forEach(k => { if (k.FreePercent < 15) flags.push([k.FreePercent < 8 ? 'bad' : 'warn', `${esc(k.Drive)} is low on space`, `${k.FreeGB} GB free of ${k.SizeGB} GB (${k.FreePercent}%).`, 'disk:' + k.Drive]); });
  const memUsed = pct(M.Used, M.Total);
  if (memUsed >= 85) flags.push(['warn', `Memory ${memUsed}% used`, `${M.Free} GB free of ${M.Total} GB.`, 'ram']);
  // Windows turns Defender off when another antivirus is active, so a disabled product only matters
  // when nothing else is running.
  const anyLive = sc.some(a => a.RealTime === 'Enabled');
  // Windows Server has no Security Center list; go by Defender's own status there.
  if (scNote && def.AntivirusEnabled !== undefined && !(def.AntivirusEnabled && def.RealTimeProtection))
    flags.push(['bad', 'Defender real-time protection is off', 'This server has no other antivirus reported. Make sure something else protects it, or turn Defender on.', 'defender-off']);
  if (sc.length && !anyLive) flags.push(['bad', 'No antivirus running', sc.map(a => `${esc(a.Name)}: ${esc(a.RealTime)}`).join(', ') + '.', 'no-av']);
  const seenAV = new Set();
  sc.forEach(a => {
    if (seenAV.has(a.Name + a.RealTime)) return;
    seenAV.add(a.Name + a.RealTime);
    if (a.RealTime === 'Enabled' && a.Definitions !== 'Up to date') flags.push(['bad', `${esc(a.Name)} definitions out of date`, 'Antivirus is running on old signatures.', 'av-old:' + a.Name.toLowerCase()]);
    if (anyLive && a.RealTime !== 'Enabled' && !/Defender/i.test(a.Name)) flags.push(['warn', `${esc(a.Name)} installed but off`, 'Another antivirus is active; remove this one if it is not wanted.', 'av-off:' + a.Name.toLowerCase()]);
  });
  // Webroot can register the same product twice; count each name once.
  const liveAV = sc.filter((a, i) => a.RealTime === 'Enabled' && sc.findIndex(b => b.Name === a.Name && b.RealTime === 'Enabled') === i);
  if (liveAV.length > 1) flags.push(['warn', `${liveAV.length} antivirus products scanning in real time`, liveAV.map(a => esc(a.Name)).join(' and ') + '. Two real-time scanners can slow a PC and conflict; usually one should be turned off.', 'two-av']);
  // One warning per product (LogMeIn and "LogMeIn Client" are one), so marking one product OK
  // does not hide a different one installed later.
  const ratProducts = new Map();
  sw.filter(s => rat.test(s.Name || '')).forEach(s => { const p = s.Name.match(rat)[0]; const k = p.toLowerCase(); if (!ratProducts.has(k)) ratProducts.set(k, { p, items: [] }); ratProducts.get(k).items.push(s); });
  ratProducts.forEach(({ p, items }, k) => flags.push(['warn', `${esc(p)} installed (remote access)`,
    items.map(s => `${esc(s.Name)} ${esc(s.Version || '')}`).join(', ') + '. Make sure it is wanted.', 'remote:' + k]));
  if (errs.length) flags.push(['warn', 'Collection error', errs.map(e => esc(typeof e === 'string' ? e : JSON.stringify(e))).join('<br>'), 'errors']);

  const active = flags.filter(f => !ACKS[f[3]]), okd = flags.filter(f => ACKS[f[3]]);
  if (!active.length) active.push(['ok', okd.length ? 'Nothing else needs attention' : 'Nothing needs attention', 'Updates, disk, memory and antivirus all look fine.', '']);
  const btn = !print;   // buttons and links only on the live page

  const diskCards = disks.map(k => { const used = 100 - k.FreePercent; return `
    <div class="card"><div class="k">Disk ${esc(k.Drive)} ${esc(k.Label || '')}</div>
    <div class="v">${k.FreeGB} GB free</div><div class="small">of ${k.SizeGB} GB, ${used}% used</div>
    <div class="bar"><span style="width:${used}%;background:${barColor(used)}"></span></div></div>`; }).join('');

  const shown = TITLE || C.Name;
  const software = sw.slice().sort((a, b) => (a.Name || '').localeCompare(b.Name || ''));
  const services = svc.slice().sort().map(s => {
    const m = /^(\S+) \((.*)\)$/.exec(s); return `<li>${m ? esc(m[2]) + ' <span>' + esc(m[1]) + '</span>' : esc(s)}</li>`; }).join('');
  const html = `
${btn && BACK ? `<a class="back" href="${esc(BACK)}">&larr; All computers</a>` : ''}
<header>
  <div><h1>${esc(shown)}</h1>${TITLE && TITLE.toUpperCase() !== String(C.Name).toUpperCase() ? `<div class="small">Windows name ${esc(C.Name)}</div>` : ''}<div class="sub">${esc(C.Manufacturer)} ${esc(C.Model)} &middot; Serial ${esc(B.SerialNumber)} &middot; ${esc(C.UserName)}</div></div>
  <div class="sub">Collected ${esc(d.Collected)}${btn && MID ? ` <button class="rs" id="rs" type="button">Rescan this PC</button>` : ''}${btn ? ` <button class="pdf" type="button" onclick="window.print()" title="Print, or choose Save as PDF as the printer">Save as PDF</button>` : ''}${btn && MID ? `<a class="rc" href="simplehelp://?JW_machine=${encodeURIComponent(MID)}" title="Open a remote control session in the SimpleHelp Technician Console">Remote control</a>` : ''}</div>
</header>
${btn ? '<div id="job" class="job" hidden></div>' : ''}

<div class="grid">
  <div class="card"><div class="k">Windows</div><div class="v">${esc((O.Name || '').replace('Microsoft ', ''))}</div>
    <div class="small">${esc(O.DisplayVersion)} &middot; build ${esc(O.Build)}</div></div>
  <div class="card"><div class="k">Processor</div><div class="v">${cpu.Cores} cores / ${cpu.LogicalProcessors} threads</div>
    <div class="small">${esc(cpu.Name)}</div>
    <div class="bar"><span style="width:${cpu.LoadPercent}%;background:${barColor(cpu.LoadPercent)}"></span></div></div>
  <div class="card"><div class="k">Memory</div><div class="v">${M.Total} GB</div><div class="small">${M.Free} GB free, ${memUsed}% used</div>
    <div class="bar"><span style="width:${memUsed}%;background:${barColor(memUsed)}"></span></div></div>
  ${diskCards}
  <div class="card"><div class="k">Uptime</div><div class="v">${Math.floor(O.UptimeDays)} days</div><div class="small">since ${esc(O.LastBoot)}</div></div>
  <div class="card"><div class="k">Last Windows update</div><div class="v">${lastPatch === null ? 'none' : lastPatch + ' days ago'}</div>
    <div class="small">${latest ? esc(latest.id) + ', ' + esc(latest.on.slice(0,10)) : ''}</div></div>
</div>

<section><h2>Needs a look</h2><ul class="flags">${active.map(([c, t, x, k]) =>
  `<li class="${c}"><b>${t}</b>${x}${btn && k ? `<button class="rs ack" type="button" data-key="${esc(k)}" data-ok="1">Mark OK</button>` : ''}</li>`).join('')}</ul>
${okd.length ? `<h3 class="okh">Marked OK (${okd.length})</h3><ul class="flags okd">${okd.map(([c, t, x, k]) =>
  `<li><b>${t}</b><span class="small">Marked OK ${esc((ACKS[k].at || '').slice(0, 10))}. ${x}</span>${btn ? `<button class="rs ack" type="button" data-key="${esc(k)}" data-ok="0">Undo</button>` : ''}</li>`).join('')}</ul>` : ''}</section>

<div class="two">
<section><h2>Computer</h2>${kv([
  ['Name', esc(C.Name)], ['Manufacturer', esc(C.Manufacturer)], ['Model', esc(C.Model)], ['Family', esc(C.Family)],
  ['Signed-in user', esc(C.UserName)], ['Registered owner', esc(C.Owner)],
  ['Domain', esc(C.Domain) + (C.PartOfDomain ? '' : ' <span class="small">(not joined)</span>')], ['Time zone', esc(C.TimeZone)],
  ['BIOS', `${esc(B.Manufacturer)} ${esc(B.Version)}`], ['BIOS date', esc((B.ReleaseDate || '').slice(0,10))], ['Serial number', `<span class="mono">${esc(B.SerialNumber)}</span>`]])}</section>
<section><h2>Operating system</h2>${kv([
  ['Edition', esc(O.Name)], ['Version', `${esc(O.DisplayVersion)} (${esc(O.Version)})`], ['Build', esc(O.Build)],
  ['Architecture', esc(O.Architecture)], ['Installed', esc(O.InstallDate)], ['Last boot', esc(O.LastBoot)],
  ['Uptime', `${O.UptimeDays} days`], ['Product ID', `<span class="mono">${esc(O.ProductID)}</span>`], ['Windows folder', esc(O.WindowsDir)]])}</section>
</div>
<div style="height:16px"></div>

<section><h2>Network</h2>${table(['Adapter', 'IP addresses', 'Gateway', 'DNS', 'MAC', 'DHCP'], nets.map(n => [
  `<b>${esc(n.Adapter)}</b>`, '<span class="mono">' + list(n.IP).map(esc).join('<br>') + '</span>',
  '<span class="mono">' + list(n.Gateway).map(esc).join('<br>') + '</span>', '<span class="mono">' + list(n.DNS).map(esc).join('<br>') + '</span>',
  `<span class="mono">${esc(n.MAC)}</span>`, yesno(n.DHCP)]))}</section>

<section><h2>Antivirus</h2>
${scNote ? `<p class="small">${esc(scNote)}</p>` : ''}
${table(['Product', 'Real-time', 'Definitions', 'State'], sc.map(a => [esc(a.Name),
  `<span class="pill ${a.RealTime === 'Enabled' ? 'ok' : 'bad'}">${esc(a.RealTime)}</span>`,
  `<span class="pill ${a.Definitions === 'Up to date' ? 'ok' : 'bad'}">${esc(a.Definitions)}</span>`, `<span class="mono">${esc(a.State)}</span>`]))}
<div style="height:12px"></div>
${kv([['Defender antivirus', yesno(def.AntivirusEnabled)], ['Defender real-time', yesno(def.RealTimeProtection)],
  ['Signature version', `${esc(def.SignatureVersion)} <span class="small">(${def.SignatureAgeDays} days old)</span>`],
  ['Last quick scan', esc(def.LastQuickScan)], ['Last full scan', def.LastFullScan ? esc(def.LastFullScan) : '<span class="small">never</span>']])}
</section>

<div class="two">
<section><h2>Printers (${prn.length})</h2>${table(['Name', 'Port', 'Default'], prn.map(p => [
  `${esc(p.Name)}<div class="small">${esc(p.Driver)}</div>`, `<span class="mono">${esc(p.Port)}</span>`, p.Default ? '<span class="pill ok">Default</span>' : '']))}</section>
<section><h2>Windows updates (${hot.length})</h2>${hot.length ? table(['Update', 'Type', 'Installed'], hot.map(h => [
  `<span class="mono">${esc(h.ID)}</span>`, esc(h.Description), esc((h.InstalledOn || '').slice(0,10))])) : '<p class="small">The hotfix list is empty on this PC; see Windows Update history below.</p>'}
${(d.UpdateHistory || []).length ? `<h2 style="margin-top:14px">Windows Update history (latest ${d.UpdateHistory.length})</h2>${table(['Update', 'Installed'], d.UpdateHistory.map(u => [esc(u.Title), esc((u.InstalledOn || '').slice(0,10))]))}` : ''}</section>
</div>
<div style="height:16px"></div>

<section><h2>Installed software (${sw.length})</h2>
  ${print ? '' : '<div class="tools"><input type="search" id="q" placeholder="Filter by name or publisher"><span class="small" id="n"></span></div>'}
  <div class="scroll"><table><thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Installed</th><th>Scope</th></tr></thead><tbody${print ? '' : ' id="sw"'}>${print ? software.map(swRow).join('') : ''}</tbody></table></div>
</section>

<section><h2>Running services (${svc.length})</h2>
  ${print ? `<ul class="svc">${services}</ul>` : `<details><summary>Show all ${svc.length}</summary><ul class="svc">${services}</ul></details>`}
</section>

<footer>From the SimpleHelp pc-report tool. Read-only snapshot; nothing on the PC was changed.</footer>`;
  return { html, software, shown };
}

window.pcReport = pcReport;
window.pcReport.swRow = swRow;
})();
