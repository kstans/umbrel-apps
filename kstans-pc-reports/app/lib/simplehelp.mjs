// SimpleHelp Integration API v1 client, trimmed from E:\AI\simplehelp-mcp\src\client.js.
// Every call is POST https://<host>/api/v1/<query> with a JSON body and a Bearer token.
import { request } from 'node:https';
import { readFileSync, existsSync } from 'node:fs';

// Settings come from the app's environment variables (set in the Umbrel app settings), or from a
// JSON file named by SIMPLEHELP_CONFIG ({ url, token, technician, connectAddress }) for local runs.
export function loadConfig(env = process.env) {
  let file = {};
  if (env.SIMPLEHELP_CONFIG && existsSync(env.SIMPLEHELP_CONFIG)) file = JSON.parse(readFileSync(env.SIMPLEHELP_CONFIG, 'utf8'));
  const url = (env.SIMPLEHELP_URL || file.url || '').trim().replace(/\/+$/, '');
  const token = (env.SIMPLEHELP_TOKEN || file.token || '').trim();
  const technician = (env.SIMPLEHELP_TECHNICIAN || file.technician || '').trim();
  const connectAddress = (env.SIMPLEHELP_CONNECT_ADDRESS || file.connectAddress || '').trim() || undefined;
  const missing = [!url && 'SIMPLEHELP_URL', !token && 'SIMPLEHELP_TOKEN', !technician && 'SIMPLEHELP_TECHNICIAN'].filter(Boolean);
  return { url, token, technician, connectAddress, missing };
}

export class SimpleHelpClient {
  constructor({ url, token, connectAddress }, { timeoutMs = 30000 } = {}) {
    this.base = `${url}/api/v1`;
    this.token = token;
    this.connectAddress = connectAddress;
    this.timeoutMs = timeoutMs;
  }

  // Never let the token reach an error message or the page.
  scrub(text) {
    return this.token ? String(text).split(this.token).join('[token]') : String(text);
  }

  async query(path, body = {}) {
    let res;
    try {
      res = await httpsPost(`${this.base}${path}`, JSON.stringify(body), this.token, this.connectAddress, this.timeoutMs);
    } catch (err) {
      throw new Error(this.scrub(`SimpleHelp ${path}: request failed: ${err.message}`));
    }
    if (res.status < 200 || res.status >= 300) throw new Error(this.scrub(`SimpleHelp ${path}: HTTP ${res.status}: ${res.text.slice(0, 300)}`));
    let data;
    try { data = res.text ? JSON.parse(res.text) : null; } catch { return res.text.trim(); }
    if (data && typeof data === 'object' && !Array.isArray(data) && data.success === false) {
      throw new Error(this.scrub(`SimpleHelp ${path}: ${data.reason || 'request rejected'}`));
    }
    return data;
  }

  listMachines() { return this.query('/machines/list', {}); }
  listTools(technician) { return this.query('/tools/list', { username: technician }); }
  runTool({ technician, toolID, machineIDs }) { return this.query('/tools/run', { username: technician, toolID, machineIDs }); }
  runStatus(runID) { return this.query('/tools/run/status', { runID }); }
  runOutput(runID) { return this.query('/tools/run/output', { runID }); }
  // Sessions on one machine (remote access, support, toolbox runs), newest first. Chat is never asked for.
  // Toolbox runs come back without a type or tool name.
  async history(machineID, since, max = 200) {
    const list = await this.query('/history/list', { machineIDFilters: [machineID], rangeStart: since, maxResults: max, includeEvents: true });
    return (Array.isArray(list) ? list : []).sort((a, b) => b.start - a.start);
  }
  // The machine's notes in SimpleHelp (the same notes the Technician Console shows).
  getNotes(machineID) { return this.query('/machines/notes/get', { machineID }); }
  setNotes(machineID, notes) { return this.query('/machines/notes/set', { machineID, notes }); }
}

// With connectAddress, the TCP connection goes to that IP (e.g. the SimpleHelp server's Tailscale
// address) while TLS still checks the certificate against the URL's hostname.
function httpsPost(url, body, token, connectAddress, timeoutMs) {
  const lookup = connectAddress
    ? (_host, opts, cb) => (opts?.all ? cb(null, [{ address: connectAddress, family: 4 }]) : cb(null, connectAddress, 4))
    : undefined;
  return new Promise((resolve, reject) => {
    // agent: false = fresh connection per call; SimpleHelp answers "Keep-Alive: timeout=0".
    const req = request(url, {
      method: 'POST', lookup, agent: false, signal: AbortSignal.timeout(timeoutMs),
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(body);
  });
}
