import express from 'express';

import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { spawn } from 'child_process';
import path from 'path';
import cors from 'cors';
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // SPA assets are static; adjust if you add inline scripts
  crossOriginEmbedderPolicy: false,
}));

// Strict JSON body limit
app.use(express.json({ limit: '64kb' }));

// CORS: single consolidated allowlist. You can extend via ALLOWED_ORIGINS env (comma-separated)
// CORS allowlist uses ALLOWED_ORIGINS env + defaults
const allowedOriginsEnv = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const defaultOrigins = ['https://techificail.web.app', 'https://techificail.firebaseapp.com'];
const allowList = Array.from(new Set([...defaultOrigins, ...allowedOriginsEnv]));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    return callback(null, allowList.includes(origin));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204,
}));
// Express 5 no longer accepts '*' path patterns; CORS middleware above already handles preflight
// Validate domain/hostname strictly
const hostnameRegex = /^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,}$/;
const ReconQuery = z.object({
  target: z.string().trim().toLowerCase().regex(hostnameRegex, 'Invalid domain'),
  mode: z.enum(['fast', 'full']).optional(),
});

const UrlScanQuery = z.object({
  target: z.string().trim().toLowerCase().regex(hostnameRegex, 'Invalid domain'),
  mode: z.enum(['fast', 'full']).optional(),
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Basic rate limiting specific to recon endpoint
const reconLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

// POST /api/recon { target }
app.post('/api/recon', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    // Fast vs Full flags
    const subfinderArgs = mode === 'full'
      ? ['-silent', '-all', '-d', target]
      : ['-silent', '-d', target];

    const httpxArgs = mode === 'full'
      ? ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '50', '-timeout', '10', '-retries', '2']
      : ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '150', '-timeout', '5', '-retries', '1'];

    // Spawn without shell and pipe safely
    const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });

    // Pipe subfinder output into httpx input
    subfinder.stdout.pipe(httpx.stdin);

    let stdout = '';
    let stderr = '';
    const outputLimitBytes = 5 * 1024 * 1024; // 5MB cap
    let totalBytes = 0;

    const killAll = (signal: NodeJS.Signals = 'SIGTERM') => {
      subfinder.kill(signal);
      httpx.kill(signal);
    };

    const killTimer = setTimeout(() => {
      killAll('SIGTERM');
    }, mode === 'full' ? 1000 * 90 : 1000 * 60);

    httpx.stdout.on('data', (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > outputLimitBytes) {
        stderr += 'Output limit exceeded';
        killAll('SIGTERM');
      } else {
        stdout += chunk.toString();
      }
    });
    const collectErr = (procName: string) => (chunk: Buffer) => { stderr += `[${procName}] ${chunk.toString()}`; };
    subfinder.stderr.on('data', collectErr('subfinder'));
    httpx.stderr.on('data', collectErr('httpx'));

    await new Promise<void>((resolve, reject) => {
      let subClosed = false;
      let httpxClosed = false;

      const maybeDone = () => {
        if (subClosed && httpxClosed) {
          clearTimeout(killTimer);
          resolve();
        }
      };

      subfinder.on('error', reject);
      httpx.on('error', reject);

      subfinder.on('close', (_code) => {
        subClosed = true;
        // Close httpx stdin to signal EOF when subfinder finishes
        try { httpx.stdin.end(); } catch {}
        maybeDone();
      });
      httpx.on('close', (code) => {
        httpxClosed = true;
        if (code !== 0 && code !== null) {
          clearTimeout(killTimer);
          reject(new Error(`httpx exited with code ${code}: ${stderr}`));
        } else {
          maybeDone();
        }
      });
    });

    const lines = stdout
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);

    const results = lines.map((line) => {
      try {
        const obj = JSON.parse(line);
        return {
          url: obj.url ?? obj.host ?? '',
          host: obj.host ?? '',
          statusCode: obj.status_code ?? obj.status ?? null,
          title: obj.title ?? '',
          technologies: obj.tech ?? obj.technologies ?? [],
        };
      } catch {
        // Fallback: parse httpx plain output "https://host [code] [title] [techs]"
        return { url: line, host: line, statusCode: null, title: '', technologies: [] };
      }
    });

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Recon failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/ports { target, mode? }
app.post('/api/ports', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    // target ports
    const portsList = mode === 'full' ? '80,443,8080,8000,8443,22,25,53,110,143,3306,3389,5900' : '80,443,8080,8000,8443';

    // Try naabu first with connect scan (non-root friendly)
    const naabuArgs = ['-host', target, '-silent', '-json', '-ports', portsList, '-scan-type', 'connect'];
    const naabu = spawn('naabu', naabuArgs, { stdio: ['ignore', 'pipe', 'pipe'] });

    let naabuStdout = '';
    let naabuStderr = '';
    const naabuTimer = setTimeout(() => { try { naabu.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 45);

    naabu.stdout.on('data', (chunk: Buffer) => { naabuStdout += chunk.toString(); });
    naabu.stderr.on('data', (chunk: Buffer) => { naabuStderr += chunk.toString(); });

    const naabuOk: boolean = await new Promise<boolean>((resolve) => {
      naabu.on('error', () => resolve(false));
      naabu.on('close', (code) => {
        clearTimeout(naabuTimer);
        resolve(code === 0 || code === null);
      });
    });

    type Finding = { host: string; ip: string; port: number };
    const findings: Finding[] = [];

    if (naabuOk) {
      // Parse naabu JSON lines
      type NaabuLine = { host?: string; ip?: string; port?: number };
      naabuStdout.split('\n').map(l => l.trim()).filter(Boolean).forEach((line) => {
        try {
          const obj = JSON.parse(line) as NaabuLine;
          if (obj && (obj.host || obj.ip) && typeof obj.port === 'number') {
            findings.push({ host: obj.host || (obj.ip as string), ip: obj.ip || '', port: obj.port });
          }
        } catch {}
      });
    } else {
      // Fallback to nmap TCP connect scan (no root needed)
      const nmapArgs = ['-Pn', '-T4', '-sT', '-p', portsList, target];
      const nmap = spawn('nmap', nmapArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      let nmapOut = '';
      let nmapErr = '';
      const nmapTimer = setTimeout(() => { try { nmap.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 45);
      nmap.stdout.on('data', (c: Buffer) => { nmapOut += c.toString(); });
      nmap.stderr.on('data', (c: Buffer) => { nmapErr += c.toString(); });
      const nmapOk = await new Promise<boolean>((resolve) => {
        nmap.on('error', () => resolve(false));
        nmap.on('close', (code) => { clearTimeout(nmapTimer); resolve(code === 0 || code === null); });
      });
      if (!nmapOk) {
        // Surface a helpful error message
        const msg = (naabuStderr || nmapErr || 'Unknown error from scanner').toString();
        throw new Error(`naabu failed and nmap fallback failed: ${msg}`);
      }
      // Parse lines like "PORT   STATE SERVICE"
      const lines = nmapOut.split('\n');
      for (const line of lines) {
        const m = line.match(/^(\d+)\/tcp\s+open\b/i);
        if (m) {
          const port = parseInt(m[1] as string, 10);
          if (!Number.isNaN(port)) {
            findings.push({ host: target, ip: '', port });
          }
        }
      }
    }

    // Build URLs to probe common web ports
    const webPorts = new Set([80, 443, 8080, 8000, 8443]);
    const urlInputs: string[] = [];
    for (const f of findings) {
      if (!webPorts.has(f.port)) continue;
      if (f.port === 443 || f.port === 8443) urlInputs.push(`https://${f.host}:${f.port}`);
      else urlInputs.push(`http://${f.host}:${f.port}`);
    }

    let probes: Record<string, { url: string; statusCode: number | null; title: string; technologies: string[] }> = {};
    if (urlInputs.length > 0) {
      const httpxArgs = mode === 'full'
        ? ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '50', '-timeout', '10', '-retries', '2']
        : ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '150', '-timeout', '5', '-retries', '1'];
      const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });

      let httpxStdout = '';
      let httpxStderr = '';
      const httpxTimer = setTimeout(() => { try { httpx.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 45);

      try {
        for (const u of urlInputs) httpx.stdin.write(u + '\n');
        httpx.stdin.end();
      } catch {}

      httpx.stdout.on('data', (chunk: Buffer) => { httpxStdout += chunk.toString(); });
      httpx.stderr.on('data', (chunk: Buffer) => { httpxStderr += chunk.toString(); });

      await new Promise<void>((resolve, reject) => {
        httpx.on('error', reject);
        httpx.on('close', (code) => {
          clearTimeout(httpxTimer);
          if (code === 0 || code === null) resolve();
          else reject(new Error(`httpx exited with code ${code}: ${httpxStderr}`));
        });
      });

      httpxStdout.split('\n').map(l => l.trim()).filter(Boolean).forEach((line) => {
        try {
          const obj = JSON.parse(line);
          const key = obj.url as string;
          probes[key] = {
            url: obj.url ?? '',
            statusCode: obj.status_code ?? obj.status ?? null,
            title: obj.title ?? '',
            technologies: obj.tech ?? obj.technologies ?? [],
          };
        } catch {}
      });
    }

    // Map back results
    const results = findings.map((f) => {
      const scheme = (f.port === 443 || f.port === 8443) ? 'https' : 'http';
      const urlKey = `${scheme}://${f.host}:${f.port}`;
      const probe = probes[urlKey];
      return {
        host: f.host,
        ip: f.ip || null,
        port: f.port,
        url: webPorts.has(f.port) ? urlKey : null,
        statusCode: probe ? probe.statusCode : null,
        title: probe ? probe.title : null,
        technologies: probe ? probe.technologies : [],
      };
    });

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Port scan failed', message: err.shortMessage || err.message || String(err) });
  }

});
// POST /api/nmap { target, mode? }
app.post('/api/nmap', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  // limits to keep runtime sane
  const maxHosts = mode === 'full' ? 100 : 40;
  const maxIps = mode === 'full' ? 60 : 20;
  const nmapTimeoutMs = mode === 'full' ? 1000 * 120 : 1000 * 60;

  try {
    // 1) subfinder -silent -d <target>
    const subfinder = spawn('subfinder', ['-silent', '-d', target], { stdio: ['ignore', 'pipe', 'pipe'] });
    let sfOut = '';
    let sfErr = '';
    subfinder.stdout.on('data', (c: Buffer) => { sfOut += c.toString(); });
    subfinder.stderr.on('data', (c: Buffer) => { sfErr += c.toString(); });
    await new Promise<void>((resolve, reject) => {
      subfinder.on('error', reject);
      subfinder.on('close', (code) => {
        if (code === 0 || code === null) resolve();
        else reject(new Error(`subfinder exited with code ${code}: ${sfErr}`));
      });
    });

    const hosts = Array.from(new Set(
      sfOut.split('\n').map(l => l.trim()).filter(Boolean)
    )).slice(0, maxHosts);

    // 2) resolve A records with dig +short
    const resolveIp = (host: string) => new Promise<string[]>((resolve) => {
      const dig = spawn('dig', ['+short', 'A', host], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      dig.stdout.on('data', (c: Buffer) => { out += c.toString(); });
      dig.on('close', () => {
        const ips = out.split('\n').map(l => l.trim()).filter(l => /^\d+\.\d+\.\d+\.\d+$/.test(l));
        resolve(ips);
      });
      dig.on('error', () => resolve([]));
    });

    const resolved = await Promise.all(hosts.map(resolveIp));
    // flatten and de-duplicate IPs
    const ips = Array.from(new Set(resolved.flat())).slice(0, maxIps);

    // 3) run nmap -p- -sV -O <ip> --script vuln*
    type NmapResult = {
      ip: string;
      openPorts: string[];
      vulnCount: number;
      summary: string;
    };

    async function scanIp(ip: string): Promise<NmapResult> {
      return new Promise<NmapResult>((resolve) => {
        const args = ['-p-', '-sV', '-O', ip, '--script', 'vuln*'];
        const nmap = spawn('nmap', args, { stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '';
        let err = '';
        const timer = setTimeout(() => { try { nmap.kill('SIGTERM'); } catch {} }, nmapTimeoutMs);

        nmap.stdout.on('data', (c: Buffer) => { out += c.toString(); });
        nmap.stderr.on('data', (c: Buffer) => { err += c.toString(); });

        nmap.on('close', () => {
          clearTimeout(timer);
          // naive parse: lines like "PORT   STATE SERVICE VERSION"
          const open: string[] = [];
          const lines = out.split('\n');
          for (const line of lines) {
            const m = line.match(/^(\d+\/tcp)\s+open\s+([^\s]+)(?:\s+(.*))?$/i);
            if (m) {
              const port = m[1];
              const svc = m[2];
              const extra = (m[3] || '').trim();
              const label = extra ? `${port} ${svc} ${extra}` : `${port} ${svc}`;
              open.push(label);
            }
          }
          const vulnCount = (out.match(/VULNERABLE/gi) || []).length;
          const summary = `open: ${open.length}, vulns: ${vulnCount}`;
          resolve({ ip, openPorts: open.slice(0, 10), vulnCount, summary });
        });

        nmap.on('error', () => resolve({ ip, openPorts: [], vulnCount: 0, summary: 'error' }));
      });
    }

    // small concurrency (2) to avoid overload
    const results: NmapResult[] = [];
    const queue = ips.slice();
    const workers = Math.min(2, queue.length);
    const runWorker = async () => {
      while (queue.length) {
        const ip = queue.shift() as string;
        const r = await scanIp(ip);
        results.push(r);
      }
    };
    await Promise.all(Array.from({ length: workers }, runWorker));

    // shape for frontend table (Recon-like rows)
    const tableResults = results.map(r => ({
      url: '', // no direct URL; leave blank
      host: r.ip,
      statusCode: null,
      title: r.summary,
      technologies: r.openPorts, // show open ports/services as tags
    }));

    res.json({ target, count: tableResults.length, results: tableResults });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Nmap scan failed', message: err.shortMessage || err.message || String(err) });
  }
});
// POST /api/js-scan { target, mode? }
app.post('/api/js-scan', reconLimiter, async (req, res) => {
  const parse = UrlScanQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    // Step 1: discover JS URLs via katana
    const katanaArgs = mode === 'full'
      ? ['-u', `https://${target}`, '-d', '5', '-jc']
      : ['-u', `https://${target}`, '-d', '3', '-jc'];

    const katana = spawn('katana', katanaArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    let katanaStdout = '';
    let katanaStderr = '';
    const katanaTimer = setTimeout(() => { try { katana.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 120 : 1000 * 60);
    katana.stdout.on('data', (c: Buffer) => { katanaStdout += c.toString(); });
    katana.stderr.on('data', (c: Buffer) => { katanaStderr += c.toString(); });
    await new Promise<void>((resolve, reject) => {
      katana.on('error', reject);
      katana.on('close', (code) => {
        clearTimeout(katanaTimer);
        if (code === 0 || code === null) resolve();
        else reject(new Error(`katana exited with code ${code}: ${katanaStderr}`));
      });
    });

    // Filter only .js URLs
    const allUrls = katanaStdout.split('\n').map(l => l.trim()).filter(Boolean);
    const jsUrls = allUrls.filter(u => /\.js(\?|#|$)/i.test(u));

    // Step 2: probe JS URLs with httpx to ensure they are reachable
    const httpxArgs = ['-silent', '-mc', '200'];
    const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
    let httpxStdout = '';
    let httpxStderr = '';
    const httpxTimer = setTimeout(() => { try { httpx.kill('SIGTERM'); } catch {} }, 1000 * 60);
    try {
      for (const u of jsUrls) httpx.stdin.write(u + '\n');
      httpx.stdin.end();
    } catch {}
    httpx.stdout.on('data', (c: Buffer) => { httpxStdout += c.toString(); });
    httpx.stderr.on('data', (c: Buffer) => { httpxStderr += c.toString(); });
    await new Promise<void>((resolve, reject) => {
      httpx.on('error', reject);
      httpx.on('close', (code) => {
        clearTimeout(httpxTimer);
        if (code === 0 || code === null) resolve();
        else reject(new Error(`httpx exited with code ${code}: ${httpxStderr}`));
      });
    });
    const liveJs = new Set(httpxStdout.split('\n').map(l => l.trim()).filter(Boolean));

    // Step 3: basic secret grep by fetching contents (simple pass)
    // We avoid external jsleak dependency here for portability; can integrate later.
    const fetchPromises: Promise<{ url: string; matches: string[] }>[] = [];
    const sensitiveRegex = /(aws_access_key|aws_secret|api_key|passwd|password|db_password|database_url|private_key|jwt_secret|access_token|authorization|bearer_token|client_secret|consumer_secret|smtp_password|ldap_password)/ig;

    const toFetch = Array.from(liveJs).slice(0, mode === 'full' ? 200 : 60);
    for (const url of toFetch) {
      fetchPromises.push(new Promise((resolve) => {
        const curl = spawn('curl', ['-sL', '--max-time', mode === 'full' ? '15' : '8', url], { stdio: ['ignore', 'pipe', 'pipe'] });
        let body = '';
        curl.stdout.on('data', (c: Buffer) => { body += c.toString(); });
        curl.on('close', () => {
          const matches = Array.from(new Set((body.match(sensitiveRegex) || []).map(m => m.toLowerCase())));
          resolve({ url, matches });
        });
        curl.on('error', () => resolve({ url, matches: [] }));
      }));
    }

    const contents = await Promise.all(fetchPromises);
    const secrets = contents
      .filter(c => c.matches.length > 0)
      .map(c => ({ url: c.url, keywords: c.matches }));

    res.json({ target, jsCount: jsUrls.length, liveCount: liveJs.size, js: Array.from(liveJs), secrets });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'JS scan failed', message: err.shortMessage || err.message || String(err) });
  }
});

const PORT = process.env.PORT || 4000;
// Serve frontend build (single URL)
const frontendDist = path.resolve(__dirname, '../../frontend/dist');
app.use(express.static(frontendDist));

// Only after API routes are defined: catch-all to index.html for SPA routing
// Use a regex that excludes /api to avoid clobbering API endpoints and avoid path-to-regexp issues
app.get(/^(?!\/api).*/, (_req, res) => {
  res.sendFile(path.join(frontendDist, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
});

