import dotenv from 'dotenv';
try { dotenv.config(); } catch {}
import express from 'express';

import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { spawn } from 'child_process';
import path from 'path';
import cors from 'cors';
import * as tls from 'tls';
import * as dns from 'dns';
import { promisify } from 'util';
import { existsSync } from 'fs';
const app = express();

// Ensure PATH contains common locations for CLI tools (e.g., ProjectDiscovery binaries in GOPATH)
// This helps when starting via npm where PATH can be limited.
try {
  const currentPath = process.env.PATH || '';
  const extraPaths = ['/usr/local/bin', '/usr/bin', '/bin', '/root/go/bin'];
  const merged = Array.from(new Set(currentPath.split(':').concat(extraPaths).filter(Boolean))).join(':');
  process.env.PATH = merged;
} catch {}

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

// Email query for breach check
const EmailQuery = z.object({
  email: z.string().trim().toLowerCase().email('Invalid email'),
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Basic rate limiting specific to recon endpoint
const reconLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
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

    let stdout = '';
    let stderr = '';
    const outputLimitBytes = 5 * 1024 * 1024; // 5MB cap
    let totalBytes = 0;

    // Step 1: Run subfinder first and capture its output
    let subdomains: string[] = [];
    let subfinderStdout = '';
    let subfinderStderr = '';
    
    try {
      const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      const subfinderTimer = setTimeout(() => { 
        try { subfinder.kill('SIGTERM'); } catch {} 
      }, mode === 'full' ? 1000 * 90 : 1000 * 60);

      subfinder.stdout.on('data', (chunk: Buffer) => { 
        subfinderStdout += chunk.toString(); 
      });
      subfinder.stderr.on('data', (chunk: Buffer) => { 
        subfinderStderr += chunk.toString(); 
      });

      await new Promise<void>((resolve) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          clearTimeout(subfinderTimer);
          resolve();
        });
        subfinder.on('close', (code) => {
          clearTimeout(subfinderTimer);
          if (code === 0 || code === null) {
            // Success - parse subdomains
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean)
            ));
            console.log(`subfinder found ${subdomains.length} subdomains for ${target}`);
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${subfinderStderr || 'no stderr'}`);
            // Still try to parse any output we got
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean)
            ));
            if (subdomains.length > 0) {
              console.log(`subfinder found ${subdomains.length} subdomains despite exit code ${code}`);
            }
          }
          resolve();
        });
      });
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}:`, sfErr?.message || sfErr);
    }

    // Step 2: If no subdomains found, use base domain
    if (subdomains.length === 0) {
      console.log(`No subdomains found for ${target}, using base domain`);
      subdomains = [target];
    }

    // Step 3: Run httpx on discovered subdomains
    try {
      const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
      const httpxTimer = setTimeout(() => { 
        try { httpx.kill('SIGTERM'); } catch {} 
      }, mode === 'full' ? 1000 * 90 : 1000 * 60);

      httpx.stdout.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > outputLimitBytes) {
          stderr += 'Output limit exceeded';
          try { httpx.kill('SIGTERM'); } catch {}
        } else {
          stdout += chunk.toString();
        }
      });
      httpx.stderr.on('data', (chunk: Buffer) => { 
        stderr += `[httpx] ${chunk.toString()}`; 
      });

      // Feed subdomains to httpx
      try {
        for (const subdomain of subdomains.slice(0, mode === 'full' ? 500 : 200)) {
          httpx.stdin.write(`https://${subdomain}\n`);
          httpx.stdin.write(`http://${subdomain}\n`);
        }
        httpx.stdin.end();
      } catch (writeErr) {
        console.error('Error writing to httpx stdin:', writeErr);
      }

      await new Promise<void>((resolve) => {
        httpx.on('error', (err) => {
          console.error(`httpx spawn error for ${target}:`, err);
          clearTimeout(httpxTimer);
          resolve();
        });
        httpx.on('close', (code) => {
          clearTimeout(httpxTimer);
          if (code === 0 || code === null) {
            console.log(`httpx completed successfully for ${target}`);
          } else {
            console.warn(`httpx exited with code ${code} for ${target}, but using output anyway`);
          }
          resolve();
        });
      });
    } catch (httpxErr: any) {
      console.error(`httpx failed for ${target}:`, httpxErr?.message || httpxErr);
    }

    const lines = stdout
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);

    let results = lines.map((line) => {
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

    // If httpx produced no results but subfinder found subdomains, return them anyway
    if (results.length === 0 && subdomains.length > 0) {
      console.log(`httpx produced no results, returning ${subdomains.length} discovered subdomains`);
      results = subdomains.map(subdomain => ({
        url: `https://${subdomain}`,
        host: subdomain,
        statusCode: null,
        title: 'Discovered (not probed)',
        technologies: ['Subdomain Discovery'],
      }));
    }

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
  const maxHosts = mode === 'full' ? 200 : 50;
  // Allow more time per host so nmap can complete service detection and scripts
  const nmapTimeoutMs = mode === 'full' ? 1000 * 300 : 1000 * 60;

  try {
    // 1) subfinder -silent -d <target>
    let hosts: string[] = [];
    try {
      const subfinder = spawn('subfinder', ['-silent', '-d', target], { stdio: ['ignore', 'pipe', 'pipe'] });
      let sfOut = '';
      let sfErr = '';
      subfinder.stdout.on('data', (c: Buffer) => { sfOut += c.toString(); });
      subfinder.stderr.on('data', (c: Buffer) => { sfErr += c.toString(); });
      await new Promise<void>((resolve) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          resolve(); // Continue with fallback
        });
        subfinder.on('close', (code) => {
          if (code === 0 || code === null) {
            resolve();
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${sfErr || 'no stderr'}`);
            resolve(); // Continue with fallback instead of rejecting
          }
        });
      });

      hosts = Array.from(new Set(
        sfOut.split('\n').map(l => l.trim()).filter(Boolean)
      )).slice(0, maxHosts);
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}, using base domain only:`, sfErr.message || sfErr);
    }
    
    // Fallback to base domain if subfinder found nothing
    if (hosts.length === 0) {
      hosts = [target];
      console.log(`No subdomains found for ${target}, using base domain`);
    }

    // 2) scan by hostname directly to preserve SNI; skip A record resolution here

    // 3) run nmap -p- -sV -O <host> --script vuln*
    type NmapResult = {
      host: string;
      ip: string;
      openPorts: string[]; // formatted labels "21/tcp ftp Microsoft ftpd"
      openCount: number;
      osGuess: string | null;
      cves: string[];
      vulnDetails: Array<{cve: string, score: string, description: string}>;
      filteredCount: number;
      closedCount: number;
      hostname: string | null;
    };

    async function scanHost(host: string): Promise<NmapResult> {
      return new Promise<NmapResult>((resolve) => {
        // -Pn: skip host discovery; -T4: faster timings; scan all ports with service/version and OS, plus vuln scripts
        const args = ['-Pn', '-T4', '-p', '80,443,8080,8000,8443', '-sV', host, '--script', 'vulners'];
        const nmap = spawn('nmap', args, { stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '';
        let err = '';
        const timer = setTimeout(() => { try { nmap.kill('SIGTERM'); } catch {} }, nmapTimeoutMs);

        nmap.stdout.on('data', (c: Buffer) => { out += c.toString(); });
        nmap.stderr.on('data', (c: Buffer) => { err += c.toString(); });

        nmap.on('close', () => {
          clearTimeout(timer);
          // Debug: log the full nmap output (uncomment for debugging)
          console.log(`Nmap output for ${host}:`, out);
          // parse open ports lines like: "21/tcp  open  ftp        Microsoft ftpd"
          const open: string[] = [];
          const lines = out.split('\n');
          let osGuess: string | null = null;
          let filteredCount = 0;
          let closedCount = 0;
          let hostname: string | null = null;
          let detectedIp: string = '';
          // capture script/service details under a port as additional tags
          let lastPortLabel: string | null = null;
          const cveSet = new Set<string>();
          const vulnDetails: Array<{cve: string, score: string, description: string}> = [];
          
          for (const line of lines) {
            // Debug: log lines that might contain CVEs (uncomment for debugging)
            if (line.includes('CVE-') || line.includes('vuln')) {
              console.log(`Processing line: ${line}`);
            }
            // Enhanced CVE parsing for vulners script output
            // Match lines like: "|       NGINX:CVE-2022-41741    7.8     https://vulners.com/nginx/NGINX:CVE-2022-41741"
            const vulnMatch = line.match(/\|\s+([A-Z0-9-:]+)\s+(\d+\.\d+)\s+(.*)/);
            if (vulnMatch && vulnMatch[1] && vulnMatch[2] && vulnMatch[3]) {
              let cve = vulnMatch[1].trim();
              const score = vulnMatch[2].trim();
              const description = vulnMatch[3].trim();
              
              // Extract just the CVE part from formats like "NGINX:CVE-2022-41741"
              if (cve.includes('CVE-')) {
                const cveMatch = cve.match(/CVE-\d{4}-\d{4,7}/i);
                if (cveMatch) {
                  const cleanCve = cveMatch[0].toUpperCase();
                  cveSet.add(cleanCve);
                  vulnDetails.push({cve: cleanCve, score, description});
                  console.log(`Found CVE: ${cleanCve} with score: ${score}`); // Debug log
                }
              }
            }
            
            // Also collect CVEs from other patterns - more comprehensive
            const cveMatches = line.match(/CVE-\d{4}-\d{4,7}/gi);
            if (cveMatches) {
              for (const c of cveMatches) {
                const cleanCve = c.toUpperCase();
                if (!cveSet.has(cleanCve)) {
                  cveSet.add(cleanCve);
                  console.log(`Found CVE from pattern match: ${cleanCve}`); // Debug log
                }
              }
            }
            
            // Try to match CVEs in different formats that might appear in nmap output
            const altCveMatch = line.match(/\|\s*([A-Z0-9-]+:CVE-\d{4}-\d{4,7})\s+(\d+\.\d+)\s+(.*)/);
            if (altCveMatch && altCveMatch[1]) {
              const cveWithPrefix = altCveMatch[1].trim();
              const cveMatch = cveWithPrefix.match(/CVE-\d{4}-\d{4,7}/i);
              if (cveMatch) {
                const cleanCve = cveMatch[0].toUpperCase();
                if (!cveSet.has(cleanCve)) {
                  cveSet.add(cleanCve);
                  console.log(`Found CVE from alt pattern: ${cleanCve}`); // Debug log
                }
              }
            }
            const m = line.match(/^\s*(\d+\/(tcp|udp))\s+open\s+([^\s]+)(?:\s+(.*))?$/i);
            if (m) {
              const port = m[1];
              const svc = m[3];
              const extra = (m[4] || '').trim();
              const label = extra ? `${port} ${svc} ${extra}` : `${port} ${svc}`;
              open.push(label);
              lastPortLabel = label;
              continue;
            }
            // Associate service/script info lines with the last seen port
            // Examples: "|_http-server-header: CloudFront"
            const scriptInfo = line.match(/^\s*\|[_\s]?([^:]+):\s*(.*)$/);
            if (scriptInfo && lastPortLabel) {
              const key = (scriptInfo[1] || '').trim();
              const val = (scriptInfo[2] || '').trim();
              if (key) {
                open.push(`${lastPortLabel} | ${key}${val ? `: ${val}` : ''}`);
              }
              continue;
            }
            // Parse report header to capture hostname
            const rep = line.match(/^\s*Nmap scan report for\s+(.+?)(?:\s*\((\d+\.\d+\.\d+\.\d+)\))?$/i);
            if (rep) {
              const name = (rep[1] || '').trim();
              const maybeIp = (rep[2] || '').trim();
              if (name && !/^\d+\.\d+\.\d+\.\d+$/.test(name)) hostname = name;
              if (maybeIp) detectedIp = maybeIp;
              continue;
            }
            // Example: "Not shown: 65533 filtered tcp ports (no-response), 202 closed tcp ports (reset)"
            const notShown = line.match(/^\s*Not shown:\s*(.*)$/i);
            if (notShown) {
              const rest = notShown[1] as string;
              const filt = rest.match(/(\d+)\s+filtered\s+tcp\s+ports/i);
              const closed = rest.match(/(\d+)\s+closed\s+tcp\s+ports/i);
              if (filt) filteredCount = parseInt(filt[1] as string, 10) || 0;
              if (closed) closedCount = parseInt(closed[1] as string, 10) || 0;
              continue;
            }
            // OS guess lines examples:
            // "Running (JUST GUESSING): OpenBSD 4.X (86%)"
            // "Aggressive OS guesses: OpenBSD 4.0 (86%)"
            // "Running: Linux 5.X"
            const os1 = line.match(/^\s*Running\s*:\s*(.*)$/i);
            const os2 = line.match(/^\s*Running \(JUST GUESSING\):\s*(.*)$/i);
            const os3 = line.match(/^\s*Aggressive OS guesses:\s*(.*)$/i);
            if (!osGuess && (os1 || os2 || os3)) {
              osGuess = (os1?.[1] || os2?.[1] || os3?.[1] || '').trim();
            }
          }
          const cves = Array.from(cveSet).slice(0, 50);
          console.log(`Host ${host}: Found ${cves.length} CVEs:`, cves); // Debug log
          // If nothing found, try a quick common-ports pass to avoid empty results on filtered hosts
          if (open.length === 0) {
            const quickArgs = ['-Pn', '-T4', '-sV', '-p', '80,443,8080,8000,8443,22,25,53,110,143,3306,3389,5900', host];
            const quick = spawn('nmap', quickArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
            let qout = '';
            quick.stdout.on('data', (c: Buffer) => { qout += c.toString(); });
            quick.on('close', () => {
              const qlines = qout.split('\n');
              for (const ql of qlines) {
                const qcves = ql.match(/CVE-\d{4}-\d{4,7}/gi);
                if (qcves) { 
                  for (const c of qcves) {
                    const cleanCve = c.toUpperCase();
                    if (!cveSet.has(cleanCve)) {
                      cveSet.add(cleanCve);
                      console.log(`Found CVE from quick scan: ${cleanCve}`); // Debug log
                    }
                  }
                }
                const m = ql.match(/^\s*(\d+\/(tcp|udp))\s+open\s+([^\s]+)(?:\s+(.*))?$/i);
                if (m) {
                  const port = m[1];
                  const svc = m[3];
                  const extra = (m[4] || '').trim();
                  const label = extra ? `${port} ${svc} ${extra}` : `${port} ${svc}`;
                  open.push(label);
                }
              }
              resolve({ host, ip: detectedIp || '', openPorts: open.slice(0, 50), openCount: open.length, osGuess, cves: Array.from(cveSet).slice(0, 50), vulnDetails: vulnDetails.slice(0, 20), filteredCount, closedCount, hostname });
            });
            return;
          }
          resolve({ host, ip: detectedIp || '', openPorts: open.slice(0, 50), openCount: open.length, osGuess: osGuess, cves, vulnDetails: vulnDetails.slice(0, 20), filteredCount, closedCount, hostname });
        });

        nmap.on('error', () => resolve({ host, ip: '', openPorts: [], openCount: 0, osGuess: null, cves: [], vulnDetails: [], filteredCount: 0, closedCount: 0, hostname: null }));
      });
    }

    // small concurrency (2) to avoid overload
    const results: NmapResult[] = [];
    const queue = hosts.slice(0, maxHosts);
    const workers = Math.min(4, queue.length);
    const runWorker = async () => {
      while (queue.length) {
        const next = queue.shift();
        if (!next) break;
        const r = await scanHost(next);
        results.push(r);
      }
    };
    await Promise.all(Array.from({ length: workers }, runWorker));

    // shape for frontend table (Recon-like rows)
    const tableResults = results.map(r => ({
      url: r.host,
      host: r.hostname ? `${r.host} (${r.ip || 'unknown IP'})` : (r.ip ? `${r.host} (${r.ip})` : r.host),
      statusCode: r.openCount,
      title: r.osGuess
        ? `${r.osGuess} | open: ${r.openCount} | filtered: ${r.filteredCount} | closed: ${r.closedCount}`
        : `open: ${r.openCount} | filtered: ${r.filteredCount} | closed: ${r.closedCount}`,
      technologies: r.openPorts,
      cves: r.cves,
      vulnDetails: r.vulnDetails,
    }));

    console.log('Final results being sent to frontend:', JSON.stringify(tableResults, null, 2)); // Debug log
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

// SSL/TLS Certificate checking utilities
const dnsLookup = promisify(dns.lookup);

interface SSLInfo {
  host: string;
  port: number;
  isValid: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  signatureAlgorithm: string | null;
  keySize: number | null;
  san: string[] | null;
  error: string | null;
}

async function checkSSLCertificate(host: string, port: number = 443): Promise<SSLInfo> {
  const result: SSLInfo = {
    host,
    port,
    isValid: false,
    issuer: null,
    subject: null,
    validFrom: null,
    validTo: null,
    daysUntilExpiry: null,
    signatureAlgorithm: null,
    keySize: null,
    san: null,
    error: null
  };

  return new Promise((resolve) => {
    const socket = tls.connect(port, host, {
      servername: host,
      rejectUnauthorized: false,
      timeout: 10000
    }, () => {
      const cert = socket.getPeerCertificate(true);
      
      if (cert && Object.keys(cert).length > 0) {
        result.isValid = true;
        result.issuer = cert.issuer?.CN || cert.issuer?.O || null;
        result.subject = cert.subject?.CN || cert.subject?.O || null;
        result.validFrom = cert.valid_from || null;
        result.validTo = cert.valid_to || null;
        result.signatureAlgorithm = (cert as any).sigalg || null;
        result.keySize = cert.bits || null;
        
        // Parse SAN (Subject Alternative Names)
        if (cert.subjectaltname) {
          result.san = cert.subjectaltname.split(',').map(name => name.trim());
        }
        
        // Calculate days until expiry
        if (result.validTo) {
          const expiryDate = new Date(result.validTo);
          const now = new Date();
          const diffTime = expiryDate.getTime() - now.getTime();
          result.daysUntilExpiry = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        }
      }
      
      socket.destroy();
      resolve(result);
    });

    socket.on('error', (err) => {
      result.error = err.message;
      socket.destroy();
      resolve(result);
    });

    socket.on('timeout', () => {
      result.error = 'Connection timeout';
      socket.destroy();
      resolve(result);
    });
  });
}

// POST /api/ssl-check { target, mode? }
app.post('/api/ssl-check', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    // First, discover subdomains using subfinder
    let subdomains: string[] = [];
    try {
      const subfinderArgs = mode === 'full'
        ? ['-silent', '-all', '-d', target]
        : ['-silent', '-d', target];

      const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      
      let subfinderStdout = '';
      let subfinderStderr = '';
      const subfinderTimer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 60);

      subfinder.stdout.on('data', (chunk: Buffer) => { subfinderStdout += chunk.toString(); });
      subfinder.stderr.on('data', (chunk: Buffer) => { subfinderStderr += chunk.toString(); });

      await new Promise<void>((resolve, reject) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          resolve(); // Continue with fallback
        });
        subfinder.on('close', (code) => {
          clearTimeout(subfinderTimer);
          if (code === 0 || code === null) {
            resolve();
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${subfinderStderr || 'no stderr'}`);
            resolve(); // Continue with fallback instead of rejecting
          }
        });
      });

      subdomains = Array.from(new Set(
        subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean)
      )).slice(0, mode === 'full' ? 200 : 100);
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}, using base domain only:`, sfErr.message || sfErr);
    }
    
    // Fallback to base domain if subfinder found nothing
    if (subdomains.length === 0) {
      subdomains = [target];
      console.log(`No subdomains found for ${target}, using base domain`);
    }

    // Check SSL certificates for each subdomain
    const sslChecks: Promise<SSLInfo>[] = [];
    const maxConcurrent = mode === 'full' ? 10 : 20;
    
    for (let i = 0; i < subdomains.length; i += maxConcurrent) {
      const batch = subdomains.slice(i, i + maxConcurrent);
      const batchPromises = batch.map(host => checkSSLCertificate(host, 443));
      sslChecks.push(...batchPromises);
    }

    const sslResults = await Promise.all(sslChecks);

    // Format results for frontend
    const results = sslResults.map(ssl => ({
      url: `https://${ssl.host}`,
      host: ssl.host,
      statusCode: ssl.isValid ? 200 : 0,
      title: ssl.isValid 
        ? `SSL Valid | Expires: ${ssl.daysUntilExpiry} days | ${ssl.issuer || 'Unknown Issuer'}`
        : `SSL Invalid | ${ssl.error || 'No certificate'}`,
      technologies: ssl.isValid ? [
        `SSL/TLS`,
        ssl.signatureAlgorithm || 'Unknown',
        ssl.keySize ? `${ssl.keySize} bits` : 'Unknown key size',
        ssl.san ? `SAN: ${ssl.san.length} domains` : 'No SAN'
      ] : ['SSL/TLS Error'],
      sslInfo: {
        isValid: ssl.isValid,
        issuer: ssl.issuer,
        subject: ssl.subject,
        validFrom: ssl.validFrom,
        validTo: ssl.validTo,
        daysUntilExpiry: ssl.daysUntilExpiry,
        signatureAlgorithm: ssl.signatureAlgorithm,
        keySize: ssl.keySize,
        san: ssl.san,
        error: ssl.error
      }
    }));

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'SSL check failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/breach-check { email }
app.post('/api/breach-check', reconLimiter, async (req, res) => {
  const parse = EmailQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { email } = parse.data;

  try {
    const apiKey = process.env.LEAKCHECK_API_KEY || 'abbda244cbe886227b9e1c4ea023f958b85e0d23';
    if (!apiKey) {
      return res.status(500).json({ error: 'API key not configured' });
    }

    const url = new URL('https://leakcheck.io/api/v2');
    url.searchParams.set('query', email);
    url.searchParams.set('type', 'email');

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'X-API-Key': apiKey,
        'Accept': 'application/json',
        'User-Agent': 'ReconApp/1.0',
      },
      signal: AbortSignal.timeout(15000),
    });

    const text = await response.text();
    if (!response.ok) {
      // LeakCheck may return text body on error
      return res.status(response.status).json({ error: 'LeakCheck error', message: text || `HTTP ${response.status}` });
    }

    let json: any;
    try { json = JSON.parse(text); } catch {
      return res.status(502).json({ error: 'Invalid response from LeakCheck', body: text.slice(0, 500) });
    }

    const success = !!json.success || typeof json.found !== 'undefined' || Array.isArray(json.breaches) || Array.isArray(json.data);
    if (!success) {
      return res.status(200).json({ email, found: false, count: 0, breaches: [] });
    }

    // Normalize to a list of breaches
    const rawBreaches: any[] = Array.isArray(json.breaches) ? json.breaches : (Array.isArray(json.data) ? json.data : []);
    const breaches = rawBreaches.map((b) => ({
      name: b.name || b.source || b.title || 'Unknown',
      date: b.date || b.time || b.added || null,
      line: b.line || null,
      password: b.password || b.pass || null,
      username: b.username || b.login || null,
      hash: b.hash || null,
      domain: b.domain || null,
      email: b.email || email,
    }));

    res.json({ email, found: breaches.length > 0, count: breaches.length, breaches: breaches.slice(0, 200) });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Breach check failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/urls-scan { target, mode? }
app.post('/api/urls-scan', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    // First, discover subdomains using subfinder
    let subdomains: string[] = [];
    let subfinderStdout = '';
    let subfinderStderr = '';
    
    try {
      const subfinderArgs = mode === 'full'
        ? ['-silent', '-all', '-d', target]
        : ['-silent', '-d', target];

      const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      
      const subfinderTimer = setTimeout(() => { 
        try { 
          subfinder.kill('SIGTERM'); 
        } catch {} 
      }, mode === 'full' ? 1000 * 90 : 1000 * 60);

      subfinder.stdout.on('data', (chunk: Buffer) => { 
        subfinderStdout += chunk.toString(); 
      });
      subfinder.stderr.on('data', (chunk: Buffer) => { 
        subfinderStderr += chunk.toString(); 
      });

      await new Promise<void>((resolve) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          clearTimeout(subfinderTimer);
          resolve(); // Continue with fallback
        });
        subfinder.on('close', (code) => {
          clearTimeout(subfinderTimer);
          if (code === 0 || code === null) {
            resolve();
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${subfinderStderr || 'no stderr'}`);
            resolve(); // Continue with fallback instead of rejecting
          }
        });
      });

      // Process output only if we got some
      if (subfinderStdout && subfinderStdout.trim().length > 0) {
        subdomains = Array.from(new Set(
          subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean)
        )).slice(0, mode === 'full' ? 100 : 50);
      }
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}, using base domain only:`, sfErr?.message || sfErr);
      // Ensure subdomains is initialized
      subdomains = [];
    }
    
    // Fallback to base domain if subfinder found nothing
    if (!subdomains || subdomains.length === 0) {
      subdomains = [target];
      console.log(`No subdomains found for ${target}, using base domain`);
    }

    // Fetch historical URLs from Wayback Machine for each subdomain
    const waybackPromises: Promise<{ subdomain: string; urls: string[] }>[] = [];
    const maxConcurrent = mode === 'full' ? 5 : 10;
    
    for (let i = 0; i < subdomains.length; i += maxConcurrent) {
      const batch = subdomains.slice(i, i + maxConcurrent);
      const batchPromises = batch.map(async (subdomain) => {
        try {
          // Construct wayback URL - use wildcard pattern for subdomains
          // For base domain, search for the domain itself and all subdomains
          const searchPattern = subdomain === target 
            ? `${subdomain}/*` 
            : `*.${subdomain}/*`;
          
          const waybackUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(searchPattern)}&collapse=urlkey&output=text&fl=original&limit=${mode === 'full' ? 100 : 50}`;
          
          const response = await fetch(waybackUrl, {
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 (compatible; ReconApp/1.0)',
            },
            signal: AbortSignal.timeout(15000) // 15 second timeout
          });
          
          if (!response.ok) {
            // Don't throw, just return empty results
            console.warn(`Wayback Machine HTTP ${response.status} for ${subdomain}`);
            return { subdomain, urls: [] };
          }
          
          const text = await response.text();
          if (!text || text.trim().length === 0) {
            return { subdomain, urls: [] };
          }
          
          const urls = text.split('\n')
            .map(line => line.trim())
            .filter(line => line && line.startsWith('http'))
            .slice(0, mode === 'full' ? 100 : 50); // Limit results
          
          return { subdomain, urls };
        } catch (error: any) {
          // Log but don't fail - return empty results
          console.error(`Wayback Machine fetch failed for ${subdomain}:`, error?.message || error);
          return { subdomain, urls: [] };
        }
      });
      waybackPromises.push(...batchPromises);
    }

    // Use Promise.allSettled to handle individual failures gracefully
    const waybackSettled = await Promise.allSettled(waybackPromises);
    const waybackResults = waybackSettled
      .filter((result): result is PromiseFulfilledResult<{ subdomain: string; urls: string[] }> => 
        result.status === 'fulfilled'
      )
      .map(result => result.value);

    // Format results for frontend - group by subdomain
    const results: any[] = [];
    const subdomainGroups: { [key: string]: string[] } = {};

    waybackResults.forEach(({ subdomain, urls }) => {
      if (urls.length > 0) {
        subdomainGroups[subdomain] = urls;
        // Add subdomain header
        results.push({
          url: `https://${subdomain}`,
          host: subdomain,
          statusCode: null,
          title: `Subdomain: ${subdomain}`,
          technologies: ['Wayback Machine', 'Historical'],
          isSubdomainHeader: true
        });
        // Add URLs for this subdomain
        urls.forEach(url => {
          try {
            const urlObj = new URL(url);
            results.push({
              url: url,
              host: urlObj.hostname,
              statusCode: null,
              title: `Historical URL`,
              technologies: ['Wayback Machine', 'Historical'],
              isSubdomainHeader: false,
              parentSubdomain: subdomain
            });
          } catch (e) {
            // Skip invalid URLs
          }
        });
      }
    });

    // Remove duplicates and limit results
    const uniqueResults = results.filter((result, index, self) => 
      index === self.findIndex(r => r.url === result.url)
    ).slice(0, mode === 'full' ? 500 : 200);

    // Always return a valid response, even if no results
    res.json({ 
      target, 
      count: uniqueResults.length, 
      results: uniqueResults,
      totalSubdomains: subdomains.length,
      subdomainsWithHistory: waybackResults.filter(r => r && r.urls && r.urls.length > 0).length
    });
  } catch (err: any) {
    console.error('URLs scan error:', err);
    // Always return a valid response structure
    res.status(500).json({ 
      error: 'URLs scan failed', 
      message: err?.shortMessage || err?.message || String(err),
      target: target || 'unknown',
      count: 0,
      results: [],
      totalSubdomains: 0,
      subdomainsWithHistory: 0
    });
  }
});

// POST /api/headers-check { target, mode? }
app.post('/api/headers-check', reconLimiter, async (req, res) => {
  // Accept URL or wildcard and normalize to a hostname before validating
  const rawTarget = (req.body && typeof req.body.target === 'string' ? req.body.target : '').trim().toLowerCase();
  const mode = (req.body && (req.body.mode === 'full' ? 'full' : 'fast')) || 'fast';
  let target = rawTarget;
  try {
    if (/^https?:\/\//i.test(rawTarget)) {
      target = new URL(rawTarget).hostname.toLowerCase();
    }
  } catch {}
  // Strip wildcard and common prefix
  if (target.startsWith('*.')) target = target.slice(2);
  if (target.startsWith('.')) target = target.slice(1);
  if (target.startsWith('www.')) target = target.slice(4);
  // Final validation as hostname
  if (!hostnameRegex.test(target)) {
    return res.status(400).json({ error: 'Invalid domain', details: { target: ['Provide a domain like example.com (URLs and wildcards are accepted and normalized).'] } });
  }

  try {
    let subdomains: string[] = [];
    try {
      const subfinderArgs = mode === 'full'
        ? ['-silent', '-all', '-d', target]
        : ['-silent', '-d', target];
      const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      let sfOut = '';
      let sfErr = '';
      const timer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 60);
      subfinder.stdout.on('data', (c: Buffer) => { sfOut += c.toString(); });
      subfinder.stderr.on('data', (c: Buffer) => { sfErr += c.toString(); });
      await new Promise<void>((resolve) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          resolve(); // Continue with fallback
        });
        subfinder.on('close', (code) => {
          clearTimeout(timer);
          if (code === 0 || code === null) {
            resolve();
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${sfErr || 'no stderr'}`);
            resolve(); // Continue with fallback instead of rejecting
          }
        });
      });

      subdomains = Array.from(new Set(sfOut.split('\n').map(l => l.trim()).filter(Boolean))).slice(0, mode === 'full' ? 150 : 60);
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}, using base domain only:`, sfErr.message || sfErr);
    }
    
    // Fallback to base domain if subfinder found nothing
    if (subdomains.length === 0) {
      subdomains = [target];
      console.log(`No subdomains found for ${target}, using base domain`);
    }
    const urls: string[] = [];
    for (const h of subdomains) {
      urls.push(`https://${h}`);
      urls.push(`http://${h}`);
    }

    type HeaderFinding = {
      url: string;
      host: string;
      statusCode: number | null;
      title: string;
      technologies: string[];
    };

    const checks = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
      'cross-origin-opener-policy',
      'cross-origin-embedder-policy',
      'cross-origin-resource-policy',
    ];

    const fetchWithTimeout = (input: string) => fetch(input, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'ReconApp/1.0' }, signal: AbortSignal.timeout(mode === 'full' ? 12000 : 6000) });

    const results: HeaderFinding[] = [];
    const max = mode === 'full' ? 200 : 100;
    const toProbe = urls.slice(0, max);
    for (const u of toProbe) {
      try {
        const r = await fetchWithTimeout(u);
        const lc = new Map<string, string>();
        r.headers.forEach((v, k) => lc.set(k.toLowerCase(), v));
        const missing = checks.filter(h => !lc.has(h));
        const present = checks.filter(h => lc.has(h)).map(h => `${h}:present`);
        const title = `${missing.length === 0 ? 'All headers present' : `Missing: ${missing.join(', ')}`}`;
        results.push({ url: u, host: new URL(u).hostname, statusCode: r.status, title, technologies: present });
      } catch (e: any) {
        results.push({ url: u, host: new URL(u).hostname, statusCode: null, title: `Error: ${(e && (e.message || String(e))) || 'request failed'}`, technologies: [] });
      }
    }

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Headers check failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/dns-hygiene { target }
app.post('/api/dns-hygiene', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;

  const resolveA = promisify(dns.resolve4);
  const resolveAAAA = promisify(dns.resolve6);
  const resolveMX = promisify(dns.resolveMx);
  const resolveTXT = promisify(dns.resolveTxt);
  const resolveNS = promisify(dns.resolveNs);
  const resolveCAA = promisify((dns as any).resolveCaa || ((_h: string, _cb: any) => _cb(new Error('CAA not supported'))));

  try {
    const [a, aaaa, mx, txt, ns] = await Promise.all([
      resolveA(target).catch(() => []),
      resolveAAAA(target).catch(() => []),
      resolveMX(target).catch(() => []),
      resolveTXT(target).catch(() => []),
      resolveNS(target).catch(() => []),
    ]);

    let caa: any[] = [];
    try { caa = await resolveCAA(target); } catch {}

    const flatTxt = (txt as string[][]).map(arr => arr.join(''));
    const spf = flatTxt.find(t => /^v=spf1\s/i.test(t)) || null;
    // DMARC lives at _dmarc.<domain>
    let dmarc: string | null = null;
    try {
      const dmarcTxt = await resolveTXT(`_dmarc.${target}`);
      const dmFlat = (dmarcTxt as string[][]).map(a => a.join(''));
      dmarc = dmFlat.find(t => /^v=DMARC1;/i.test(t)) || null;
    } catch {}

    const hygieneFindings: Array<{ url: string; host: string; statusCode: number | null; title: string; technologies: string[] }> = [];

    hygieneFindings.push({ url: `dns://${target}`, host: target, statusCode: (a as string[]).length + (aaaa as string[]).length, title: `A/AAAA: ${(a as string[]).join(', ')} ${(aaaa as string[]).join(', ')}`.trim(), technologies: ['A', 'AAAA'] });
    hygieneFindings.push({ url: `dns://${target}/mx`, host: target, statusCode: (mx as any[]).length, title: mx && (mx as any[]).length ? `MX ok (${(mx as any[]).map((m: any) => `${m.exchange}:${m.priority}`).join(', ')})` : 'No MX records', technologies: ['MX'] });
    hygieneFindings.push({ url: `dns://${target}/spf`, host: target, statusCode: spf ? 200 : 0, title: spf ? `SPF: ${spf}` : 'SPF missing', technologies: ['SPF'] });
    hygieneFindings.push({ url: `dns://${target}/dmarc`, host: target, statusCode: dmarc ? 200 : 0, title: dmarc ? `DMARC: ${dmarc}` : 'DMARC missing', technologies: ['DMARC'] });
    hygieneFindings.push({ url: `dns://${target}/ns`, host: target, statusCode: (ns as string[]).length, title: ns && (ns as string[]).length ? `NS: ${(ns as string[]).join(', ')}` : 'No NS records', technologies: ['NS'] });
    hygieneFindings.push({ url: `dns://${target}/caa`, host: target, statusCode: caa.length, title: caa && caa.length ? `CAA present (${caa.length})` : 'No CAA records', technologies: ['CAA'] });

    res.json({ target, count: hygieneFindings.length, results: hygieneFindings });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'DNS hygiene failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/reputation { target }
app.post('/api/reputation', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;

  try {
    const vtKey = process.env.VIRUSTOTAL_API_KEY || '';
    const gsbKey = process.env.GSB_API_KEY || '';
    const results: Array<{ url: string; host: string; statusCode: number | null; title: string; technologies: string[] }> = [];

    if (vtKey) {
      try {
        const vtResp = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(target)}`, {
          headers: { 'x-apikey': vtKey, 'User-Agent': 'ReconApp/1.0' },
          signal: AbortSignal.timeout(12000),
        });
        const vtJson: any = await vtResp.json().catch(() => ({}));
        const cats = vtJson?.data?.attributes?.categories || {};
        const rep = vtJson?.data?.attributes?.reputation ?? null;
        const harmless = vtJson?.data?.attributes?.last_analysis_stats?.harmless ?? 0;
        const malicious = vtJson?.data?.attributes?.last_analysis_stats?.malicious ?? 0;
        results.push({ url: `vt://${target}`, host: target, statusCode: vtResp.status, title: `VT rep=${rep} harmless=${harmless} malicious=${malicious}`, technologies: Object.values(cats) as string[] });
      } catch (e: any) {
        results.push({ url: `vt://${target}`, host: target, statusCode: null, title: `VT error: ${(e && (e.message || String(e))) || 'failed'}`, technologies: [] });
      }
    }

    if (gsbKey) {
      try {
        const gsbBody = {
          client: { clientId: 'recon-app', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: `http://${target}` }, { url: `https://${target}` }]
          }
        } as any;
        const gsbResp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(gsbBody),
          signal: AbortSignal.timeout(12000),
        });
        const gsbJson: any = await gsbResp.json().catch(() => ({}));
        const matches = Array.isArray(gsbJson?.matches) ? gsbJson.matches : [];
        results.push({ url: `gsb://${target}`, host: target, statusCode: gsbResp.status, title: matches.length ? `GSB matches: ${matches.map((m: any) => m.threatType).join(', ')}` : 'GSB: no matches', technologies: ['GSB'] });
      } catch (e: any) {
        results.push({ url: `gsb://${target}`, host: target, statusCode: null, title: `GSB error: ${(e && (e.message || String(e))) || 'failed'}`, technologies: [] });
      }
    }

    if (!vtKey && !gsbKey) {
      results.push({ url: `rep://${target}`, host: target, statusCode: 0, title: 'No API keys configured for reputation. Set VIRUSTOTAL_API_KEY and/or GSB_API_KEY.', technologies: [] });
    }

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Reputation check failed', message: err.shortMessage || err.message || String(err) });
  }
});

// POST /api/cloud-buckets { target }
app.post('/api/cloud-buckets', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;

  try {
    const root = target.replace(/^\*\.?/, '');
    const base = root.replace(/^www\./, '');
    const nameCandidatesSet = new Set<string>();
    const baseParts = base ? base.split('.') : [];
    const rootLabel = (baseParts[0] || base || '').trim();
    const primaries: Array<string | undefined> = [
      base,
      base ? base.replace(/\./g, '-') : undefined,
      baseParts.length ? baseParts.join('') : undefined,
      rootLabel || undefined,
      rootLabel ? `${rootLabel}-static` : undefined,
      rootLabel ? `${rootLabel}-assets` : undefined,
      base ? `${base}-assets` : undefined,
      base ? `${base}-public` : undefined,
    ];
    for (const c of primaries) if (c && c.length > 0) nameCandidatesSet.add(c);

    // Enrich candidates using discovered subdomains (best-effort)
    try {
      const sfArgs = ['-silent', '-d', root];
      const subfinder = spawn('subfinder', sfArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      let sfOut = '';
      let sfErr = '';
      const sfTimer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, 1000 * 45);
      subfinder.stdout.on('data', (c: Buffer) => { sfOut += c.toString(); });
      subfinder.stderr.on('data', (c: Buffer) => { sfErr += c.toString(); });
      await new Promise<void>((resolve) => {
        subfinder.on('error', () => resolve());
        subfinder.on('close', () => { clearTimeout(sfTimer); resolve(); });
      });
      const subs = Array.from(new Set(sfOut.split('\n').map(l => l.trim()).filter(Boolean))).slice(0, 50);
      for (const s of subs) {
        const h = s.replace(/^\*\.?/, '').replace(/^www\./, '');
        nameCandidatesSet.add(h);
        nameCandidatesSet.add(h.replace(/\./g, '-'));
        nameCandidatesSet.add(h.split('.').join(''));
      }
    } catch {}

    const nameCandidates = Array.from(nameCandidatesSet);

    type BucketFinding = { url: string; host: string; statusCode: number | null; title: string; technologies: string[] };
    const findings: BucketFinding[] = [];

    async function tryUrl(u: string, label: string) {
      try {
        const r = await fetch(u, { method: 'GET', headers: { 'User-Agent': 'ReconApp/1.0' }, signal: AbortSignal.timeout(8000) });
        const text = await r.text().catch(() => '');
        const open = r.ok && /<ListBucketResult|<EnumerationResults|<Error>|\{"kind":"storage#objects"/.test(text);
        let host = '';
        try {
          host = new URL(u).host;
        } catch {
          host = u.split('/')[2] || u;
        }
        findings.push({ url: u, host, statusCode: r.status, title: `${label}: ${open ? 'Public or queryable' : 'Not public'} (${r.status})`, technologies: [label] });
      } catch (e: any) {
        let host = '';
        try {
          host = new URL(u).host;
        } catch {
          host = u.split('/')[2] || u;
        }
        findings.push({ url: u, host, statusCode: null, title: `${label}: error ${(e && (e.message || String(e))) || 'failed'}` , technologies: [label]});
      }
    }

    async function tryAwsCli(name: string) {
      return new Promise<void>((resolve) => {
        try {
          const args = ['s3', 'ls', `s3://${name}/`, '--no-sign-request'];
          const aws = spawn('aws', args, { stdio: ['ignore', 'pipe', 'pipe'] });
          let out = '';
          let err = '';
          const timer = setTimeout(() => { try { aws.kill('SIGTERM'); } catch {} }, 1000 * 8);
          aws.stdout.on('data', (c: Buffer) => { out += c.toString(); });
          aws.stderr.on('data', (c: Buffer) => { err += c.toString(); });
          aws.on('close', (code) => {
            clearTimeout(timer);
            const hasList = (out.trim().length > 0) && (code === 0 || code === null);
            const host = `${name}.s3.amazonaws.com`;
            findings.push({
              url: `s3://${name}/`,
              host,
              statusCode: hasList ? 200 : 0,
              title: hasList ? 'AWS S3 (CLI): Public listing available' : `AWS S3 (CLI): Not public${err ? ` (${(err.split('\n')[0] || '').trim()})` : ''}`,
              technologies: ['AWS S3 (CLI)']
            });
            resolve();
          });
          aws.on('error', () => resolve());
        } catch { resolve(); }
      });
    }

    for (const name of nameCandidates.slice(0, 20)) {
      await Promise.all([
        tryUrl(`http://${name}.s3.amazonaws.com/?list-type=2`, 'AWS S3'),
        tryUrl(`https://storage.googleapis.com/storage/v1/b/${name}/o`, 'GCS'),
        tryUrl(`https://${name}.blob.core.windows.net/?comp=list`, 'Azure Blob'),
      ]);
      // Best-effort AWS CLI probe (if aws installed)
      await tryAwsCli(name);
    }

    if (findings.length === 0) {
      findings.push({
        url: `cloud://${target}`,
        host: target,
        statusCode: 0,
        title: 'No public buckets detected for common names',
        technologies: ['S3', 'GCS', 'Azure']
      });
    }

    res.json({ target, count: findings.length, results: findings });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Cloud bucket check failed', message: err.shortMessage || err.message || String(err) });
  }
});

const PORT = parseInt(process.env.PORT || '4000', 10);
// Serve frontend build (optional - only if it exists, since frontend is deployed separately)
const frontendDist = path.resolve(__dirname, '../../frontend/dist');
if (existsSync(frontendDist)) {
app.use(express.static(frontendDist));
// Only after API routes are defined: catch-all to index.html for SPA routing
// Use a regex that excludes /api to avoid clobbering API endpoints and avoid path-to-regexp issues
app.get(/^(?!\/api).*/, (_req, res) => {
  res.sendFile(path.join(frontendDist, 'index.html'));
});
} else {
  // Frontend not available - that's okay, it's deployed separately
  console.log('Frontend dist not found - serving API only');
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend listening on http://0.0.0.0:${PORT}`);
});

