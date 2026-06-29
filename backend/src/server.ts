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
import { existsSync, writeFileSync, readFileSync, unlinkSync, mkdirSync, readdirSync } from 'fs';
import { randomUUID } from 'crypto';
import {
  fetchCrtShHostnames,
  fetchVirusTotalDomain,
  parseBbotOutputDirectory,
  resolveIpsForHosts,
  addIpSource,
  ipMapToRows,
  writeDiscoveryOutputFile,
  isUnderTarget,
  normalizeHostname,
  type IpSourceMap,
} from './discovery-helpers';
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
// Allow localhost origins for local development (common Vite ports)
const localhostOrigins = [
  'http://localhost:5173', // Vite default
  'http://localhost:5174', // Vite alternate
  'http://localhost:5175', // Vite alternate
  'http://localhost:3000', // Common React dev port
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174',
  'http://127.0.0.1:5175',
  'http://127.0.0.1:3000',
];
const allowList = Array.from(new Set([...localhostOrigins, ...allowedOriginsEnv]));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    // Allow any localhost/127.0.0.1 origin for local development
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return callback(null, true);
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

// Helper function to check if a string is an IP address
function isIPAddress(str: string): boolean {
  // IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(str)) {
    const parts = str.split('.');
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }
  // IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
  return ipv6Regex.test(str);
}

// Helper function to extract hostname from URL
function extractHostname(url: string): string {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    // If URL parsing fails, try to extract manually
    const match = url.match(/^https?:\/\/([^\/:]+)/);
    return match && match[1] ? match[1] : url;
  }
}

// Helper function to validate domain names and filter out error messages
function isValidDomain(line: string): boolean {
  // Filter out error messages, paths, and invalid strings
  if (!line || line.length === 0) return false;
  if (line.includes('/') || line.includes('\\')) return false; // Paths
  if (line.includes('no such file') || line.includes('error') || line.includes('Error')) return false;
  if (line.startsWith('open ') || line.startsWith('failed') || line.startsWith('cannot')) return false;
  if (line.includes('.config') || line.includes('.yaml')) return false; // Config file paths
  if (line.includes('getaddrinfo') || line.includes('ENOTFOUND')) return false; // DNS errors
  // Filter out IP addresses
  if (isIPAddress(line)) return false;
  // Basic domain validation: should contain at least one dot and valid characters
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  return domainRegex.test(line);
}
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

// Prompt injection query schema (YAML only mode)
const PromptInjectionQuery = z.object({
  target: z.string().trim().min(1, 'Target URL is required'),
  httpConfigYaml: z.string().trim().min(1, 'YAML configuration is required'),
  controllerModel: z.string().optional().default('gpt-4o'),
  controllerModelType: z.enum(['openai', 'anthropic', 'ollama']).optional().default('openai'),
  iterations: z.number().int().min(1).max(10).optional().default(3),
  rules: z.array(z.string()).optional(),
  ruleTypes: z.array(z.string()).optional(),
  firewall: z.boolean().optional().default(false),
  passCondition: z.string().optional(),
});

// Garak LLM vulnerability scan query
// Notes:
// - garak's CLI takes --target_type (-m) and --target_name (-n). The previous API used a single `model` string.
// - For scanning external chatbot HTTP endpoints, use `targetType: "rest.RestGenerator"` and pass the endpoint URL as targetName,
//   with `generatorOptions` defining request template, headers, and response extraction.
const GarakScanQuery = z.object({
  // Optional label for display only (e.g. "hacktheagent /api/chat")
  targetLabel: z.string().trim().optional(),

  // New-style garak CLI parameters
  targetType: z.string().trim().optional(), // e.g. "rest.RestGenerator", "openai", "openai.OpenAIGenerator"
  targetName: z.string().trim().optional(), // e.g. URL for rest, model name for openai
  generations: z.number().int().min(1).max(20).optional(),

  // Generator options passed to garak via --generator_option_file as JSON
  // (e.g. for rest.RestGenerator: { method, headers, req_template_json_object, response_json, response_json_field })
  generatorOptions: z.record(z.string(), z.any()).optional(),

  // Convenience fields for the common "scan an HTTP chatbot endpoint" use-case
  // This is turned into targetType=rest.RestGenerator + generatorOptions internally.
  httpTarget: z.object({
    uri: z.string().trim().min(1),
    method: z.string().trim().optional().default('post'),
    headers: z.record(z.string(), z.string()).optional().default({}),
    reqTemplateJsonObject: z.record(z.string(), z.any()).optional(),
    reqTemplate: z.string().optional(), // raw string template with $INPUT; if set, takes precedence over reqTemplateJsonObject
    reqTemplateFormData: z.record(z.string(), z.string()).optional(), // multipart/form-data fields; one field should contain "$INPUT"
    responseJsonField: z.string().trim().optional().default('$.bot_response.response'),
    requestTimeout: z.number().int().min(1).max(120).optional().default(20),
    verifySsl: z.boolean().optional().default(true),
  }).optional(),

  // Probes list, e.g. ["promptinject", "dan", "xss"]
  probes: z.array(z.string().trim()).optional(),

  // Optional extra CLI arguments passed directly to garak (advanced use only)
  extraArgs: z.string().trim().optional(),

  // Backward compatibility: previous UI posted `{ model: "..." }`
  model: z.string().trim().optional(),
});

function safeMkdir(p: string) {
  try { mkdirSync(p, { recursive: true }); } catch {}
}

// ── Wayback prefetch cache ────────────────────────────────────────────────
// Keyed by target domain. Persisted to disk so nodemon restarts don't wipe it.
type WaybackCache = {
  status: 'running' | 'done';
  results: Map<string, string[]>; // subdomain -> urls
  startedAt: number;
};
const waybackCache = new Map<string, WaybackCache>();

const WAYBACK_CACHE_DIR = path.join(process.cwd(), '.wayback-cache');
safeMkdir(WAYBACK_CACHE_DIR);

function waybackCacheFile(target: string): string {
  return path.join(WAYBACK_CACHE_DIR, `${target.replace(/[^a-z0-9.-]/gi, '_')}.json`);
}

function loadWaybackCacheFromDisk(target: string): WaybackCache | null {
  try {
    const file = waybackCacheFile(target);
    if (!existsSync(file)) return null;
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    // Expire after 2 hours
    if (Date.now() - raw.startedAt > 2 * 60 * 60 * 1000) {
      unlinkSync(file);
      return null;
    }
    return { status: raw.status, results: new Map(Object.entries(raw.results)), startedAt: raw.startedAt };
  } catch { return null; }
}

function saveWaybackCacheToDisk(target: string, cache: WaybackCache): void {
  try {
    const file = waybackCacheFile(target);
    writeFileSync(file, JSON.stringify({
      status: cache.status,
      results: Object.fromEntries(cache.results),
      startedAt: cache.startedAt,
    }), 'utf8');
  } catch {}
}

// Static asset extensions to filter out — not useful for recon
const STATIC_EXT_RE = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|webp|avif|mp4|mp3|pdf|zip|gz|tar|wasm)(\?|$)/i;

async function fetchWaybackForSubdomain(subdomain: string): Promise<{ subdomain: string; urls: string[] }> {
  // Use *.subdomain/* wildcard to catch all paths AND sub-subdomains
  const searchPattern = `*.${subdomain}/*`;
  const waybackUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(searchPattern)}&collapse=urlkey&output=text&fl=original&filter=statuscode:200`;

  const MAX_RETRIES = 3;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      // Give more time on later retries
      const timeoutMs = attempt === 1 ? 30000 : attempt === 2 ? 45000 : 60000;
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(waybackUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ReconApp/1.0)' },
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (!response.ok) {
          if (response.status === 429 || response.status >= 500) {
            // Rate limited or server error — wait and retry
            await new Promise(r => setTimeout(r, attempt * 3000));
            continue;
          }
          return { subdomain, urls: [] };
        }
        const text = await response.text();
        if (!text?.trim()) return { subdomain, urls: [] };
        const urls = text.split('\n')
          .map(l => l.trim())
          .filter(l => l && l.startsWith('http') && !STATIC_EXT_RE.test(l));
        return { subdomain, urls };
      } finally {
        clearTimeout(timer);
      }
    } catch (err: any) {
      const isTimeout = err?.name === 'AbortError' || err?.message?.includes('abort');
      console.warn(`[wayback] attempt ${attempt}/${MAX_RETRIES} failed for ${subdomain}: ${err?.message}`);
      if (attempt < MAX_RETRIES) {
        // Exponential backoff: 2s, 5s
        await new Promise(r => setTimeout(r, attempt * (isTimeout ? 2000 : 1000)));
      }
    }
  }
  return { subdomain, urls: [] };
}

function getOrLoadWaybackCache(target: string): WaybackCache | null {
  if (waybackCache.has(target)) return waybackCache.get(target)!;
  const disk = loadWaybackCacheFromDisk(target);
  if (disk) { waybackCache.set(target, disk); return disk; }
  return null;
}

async function runWaybackPrefetch(target: string, subdomains: string[]): Promise<void> {
  const existing = getOrLoadWaybackCache(target);
  if (existing) return; // already running or done

  const cache: WaybackCache = { status: 'running', results: new Map(), startedAt: Date.now() };
  waybackCache.set(target, cache);

  const concurrency = 4; // be polite to Wayback
  for (let i = 0; i < subdomains.length; i += concurrency) {
    const batch = subdomains.slice(i, i + concurrency);
    const results = await Promise.all(batch.map(s => fetchWaybackForSubdomain(s)));
    for (const r of results) {
      if (r.urls.length > 0) cache.results.set(r.subdomain, r.urls);
    }
    // Persist incrementally so partial results survive restarts
    saveWaybackCacheToDisk(target, cache);
  }

  cache.status = 'done';
  saveWaybackCacheToDisk(target, cache);
  console.log(`[wayback-prefetch] done for ${target}: ${cache.results.size} subdomains with history`);

  // Evict from memory after 2 hours (disk copy stays until expired)
  setTimeout(() => waybackCache.delete(target), 2 * 60 * 60 * 1000);
}

function parseJsonlDigest(reportPath: string): any | null {
  try {
    const content = readFileSync(reportPath, 'utf8');
    const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const line = lines[i];
        if (!line) continue;
        const obj = JSON.parse(line);
        if (obj && obj.entry_type === 'digest') return obj;
      } catch {}
    }
    return null;
  } catch {
    return null;
  }
}

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Debug endpoint to check environment variables (remove in production if needed)
app.get('/api/debug/env', (_req, res) => {
  res.json({
    hasVtKey: !!process.env.VIRUSTOTAL_API_KEY,
    hasGsbKey: !!process.env.GSB_API_KEY,
    vtKeyLength: process.env.VIRUSTOTAL_API_KEY?.length || 0,
    gsbKeyLength: process.env.GSB_API_KEY?.length || 0,
    vtKeyPrefix: process.env.VIRUSTOTAL_API_KEY?.substring(0, 10) || 'not set',
    gsbKeyPrefix: process.env.GSB_API_KEY?.substring(0, 10) || 'not set',
  });
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
          
          // Check if there are errors in stderr
          const hasConfigError = subfinderStderr.includes('config.yaml') || subfinderStderr.includes('no such file');
          if (hasConfigError) {
            console.warn(`subfinder config error for ${target}: ${subfinderStderr.substring(0, 200)}`);
          }

          if (code === 0 || code === null) {
            // Success - parse subdomains and filter out errors
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n')
                .map(l => l.trim())
                .filter(Boolean)
                .filter(isValidDomain)
            ));
            if (subdomains.length > 0) {
              console.log(`subfinder found ${subdomains.length} subdomains for ${target}`);
            } else {
              console.warn(`subfinder completed but found no valid domains. stdout: "${subfinderStdout.substring(0, 200)}", stderr: "${subfinderStderr.substring(0, 200)}"`);
            }
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${subfinderStderr || 'no stderr'}`);
            // Still try to parse any output we got, but filter errors
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n')
                .map(l => l.trim())
                .filter(Boolean)
                .filter(isValidDomain)
            ));
            if (subdomains.length > 0) {
              console.log(`subfinder found ${subdomains.length} subdomains despite exit code ${code}`);
            } else {
              console.warn(`subfinder output contained no valid domains. stdout: "${subfinderStdout.substring(0, 200)}", stderr: "${subfinderStderr.substring(0, 200)}"`);
            }
          }
          resolve();
        });
      });
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}:`, sfErr?.message || sfErr);
    }

    const subfinderHostCount = subdomains.length;

    function mergedHostEntry(raw: string): string | null {
      const h = normalizeHostname(raw).replace(/^\*\./, '');
      if (!isUnderTarget(h, target)) return null;
      if (!isValidDomain(h)) return null;
      return h;
    }

    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    const bbotBase = process.env.BBOT_OUTPUT_DIR || path.join(process.cwd(), 'bbot-output');
    const safeTargetDir = target.replace(/[^a-z0-9.-]/gi, '_');
    const explicitBbot = process.env.BBOT_SCAN_PATH?.trim();
    const bbotDir =
      explicitBbot && existsSync(explicitBbot)
        ? explicitBbot
        : path.join(bbotBase, safeTargetDir);

    const [crtNames, vtData, bbotData] = await Promise.all([
      fetchCrtShHostnames(target),
      fetchVirusTotalDomain(target, vtKey),
      Promise.resolve(parseBbotOutputDirectory(bbotDir, target)),
    ]);

    const mergedSubs = new Set<string>();
    for (const s of subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of crtNames) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of vtData.subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of bbotData.subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }

    subdomains = Array.from(mergedSubs);
    if (subdomains.length === 0) {
      console.log(`No subdomains found for ${target}, using base domain`);
      subdomains = [target];
    }

    const ipSources: IpSourceMap = new Map();
    for (const ip of vtData.ips) addIpSource(ipSources, ip, 'virustotal');
    for (const ip of bbotData.ips) addIpSource(ipSources, ip, 'bbot');
    const dnsCap = mode === 'full' ? 150 : 80;
    const dnsIps = await resolveIpsForHosts(subdomains, dnsCap);
    for (const ip of dnsIps) addIpSource(ipSources, ip, 'dns');

    let discoveryOutPath: string | null = null;
    try {
      const outDir = process.env.RECON_OUTPUT_DIR || path.join(process.cwd(), 'recon-output');
      const allIpsSorted = Array.from(ipSources.keys()).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      discoveryOutPath = writeDiscoveryOutputFile(outDir, target, subdomains, allIpsSorted, {
        subfinder: subfinderHostCount,
        crtSh: crtNames.length,
        virusTotalHosts: vtData.subdomains.length,
        virusTotalIps: vtData.ips.length,
        bbotHosts: bbotData.subdomains.length,
        bbotIps: bbotData.ips.length,
        mergedSubdomains: subdomains.length,
        mergedIps: allIpsSorted.length,
      });
    } catch (wErr) {
      console.warn('writeDiscoveryOutputFile failed:', wErr);
    }

    const ipResults = ipMapToRows(ipSources);

    const mergedSubdomainsSorted = [...subdomains].sort((a, b) => a.localeCompare(b));
    const envHttpxMax = parseInt(process.env.HTTPX_MAX_HOSTS || '', 10);
    const httpxMaxHosts =
      Number.isFinite(envHttpxMax) && envHttpxMax > 0
        ? Math.min(envHttpxMax, 20000)
        : mode === 'full'
          ? 5000
          : 1200;
    const httpxInput = mergedSubdomainsSorted.slice(0, httpxMaxHosts);
    if (mergedSubdomainsSorted.length > httpxMaxHosts) {
      console.warn(
        `httpx input capped: ${httpxMaxHosts}/${mergedSubdomainsSorted.length} hosts (set HTTPX_MAX_HOSTS or use mode=full)`
      );
    }

    // Run httpx on merged subdomain list (subset — full inventory is mergedSubdomainsSorted / output file)
    try {
      const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
      const httpxTimer = setTimeout(() => { 
        try { httpx.kill('SIGTERM'); } catch {} 
      }, mode === 'full' ? 1000 * 180 : 1000 * 120);

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
        for (const subdomain of httpxInput) {
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
        const url = obj.url ?? obj.host ?? '';
        let host = obj.host ?? '';
        
        // Extract hostname from URL if host is an IP address or empty
        if (isIPAddress(host) || !host) {
          host = extractHostname(url);
        }
        
        // Skip if host is still an IP address
        if (isIPAddress(host)) {
          return null;
        }
        
        return {
          url: url,
          host: host,
          statusCode: obj.status_code ?? obj.status ?? null,
          title: obj.title ?? '',
          technologies: obj.tech ?? obj.technologies ?? [],
        };
      } catch {
        // Fallback: parse httpx plain output "https://host [code] [title] [techs]"
        const hostname = extractHostname(line);
        if (isIPAddress(hostname)) {
          return null;
        }
        return { url: line, host: hostname, statusCode: null, title: '', technologies: [] };
      }
    }).filter((r): r is NonNullable<typeof r> => r !== null);

    // Deduplicate results by URL (normalize to lowercase for comparison)
    const seenUrls = new Set<string>();
    results = results.filter(result => {
      const normalizedUrl = result.url.toLowerCase();
      if (seenUrls.has(normalizedUrl)) {
        return false;
      }
      seenUrls.add(normalizedUrl);
      return true;
    });

    // If httpx produced no results but we have a merged inventory, surface it in the table
    if (results.length === 0 && mergedSubdomainsSorted.length > 0) {
      console.log(`httpx produced no results, returning ${mergedSubdomainsSorted.length} discovered subdomains`);
      results = mergedSubdomainsSorted.map((subdomain) => ({
        url: `https://${subdomain}`,
        host: subdomain,
        statusCode: null,
        title: 'Discovered (not probed)',
        technologies: ['httpx (offline)', 'merged: subfinder + crt.sh + VT + bbot'],
      }));
    }

    console.log(
      `recon inventory for ${target}: merged=${mergedSubdomainsSorted.length} subfinder=${subfinderHostCount} crt=${crtNames.length} vt_hosts=${vtData.subdomains.length} bbot_hosts=${bbotData.subdomains.length} httpx_rows=${results.length}`
    );

    res.json({
      target,
      count: results.length,
      results,
      mergedCount: mergedSubdomainsSorted.length,
      mergedSubdomains: mergedSubdomainsSorted,
      ipCount: ipResults.length,
      ipResults,
      discovery: {
        subfinder: subfinderHostCount,
        crtSh: crtNames.length,
        virusTotal: { hosts: vtData.subdomains.length, ips: vtData.ips.length },
        bbot: { hosts: bbotData.subdomains.length, ips: bbotData.ips.length },
        bbotDir,
        outputFile: discoveryOutPath,
        httpxInputHosts: httpxInput.length,
        httpxMaxHosts,
      },
    });
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
    const portsList = mode === 'full'
      ? '80,443,8080,8000,8443,22,25,53,110,143,3306,3389,5900'
      : '80,443,8080,8000,8443';
    const ports = portsList.split(',').map(p => parseInt(p, 10)).filter(n => Number.isFinite(n) && n > 0);

    // 1) Build IP inventory from the same discovery sources as /api/recon (VT + BBot + DNS over merged host inventory)
    let subdomainsForIp: string[] = [];
    let subfinderStdout = '';
    let subfinderStderr = '';
    try {
      const subfinder = spawn('subfinder', mode === 'full' ? ['-silent', '-all', '-d', target] : ['-silent', '-d', target], { stdio: ['ignore', 'pipe', 'pipe'] });
      const subfinderTimer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 120 : 1000 * 75);
      subfinder.stdout.on('data', (chunk: Buffer) => { subfinderStdout += chunk.toString(); });
      subfinder.stderr.on('data', (chunk: Buffer) => { subfinderStderr += chunk.toString(); });
      await new Promise<void>((resolve) => {
        subfinder.on('error', () => resolve());
        subfinder.on('close', () => { clearTimeout(subfinderTimer); resolve(); });
      });
    } catch {}
    try {
      subdomainsForIp = Array.from(new Set(
        subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)
      ));
    } catch {}

    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    const bbotBase = process.env.BBOT_OUTPUT_DIR || path.join(process.cwd(), 'bbot-output');
    const safeTargetDir = target.replace(/[^a-z0-9.-]/gi, '_');
    const explicitBbot = process.env.BBOT_SCAN_PATH?.trim();
    const bbotDir =
      explicitBbot && existsSync(explicitBbot)
        ? explicitBbot
        : path.join(bbotBase, safeTargetDir);

    const [crtNames, vtData, bbotData] = await Promise.all([
      fetchCrtShHostnames(target),
      fetchVirusTotalDomain(target, vtKey),
      Promise.resolve(parseBbotOutputDirectory(bbotDir, target)),
    ]);

    function mergedHostEntry(raw: string): string | null {
      const h = normalizeHostname(raw).replace(/^\*\./, '');
      if (!isUnderTarget(h, target)) return null;
      if (!isValidDomain(h)) return null;
      return h;
    }

    const mergedHosts = new Set<string>();
    for (const s of subdomainsForIp) { const m = mergedHostEntry(s); if (m) mergedHosts.add(m); }
    for (const s of crtNames) { const m = mergedHostEntry(s); if (m) mergedHosts.add(m); }
    for (const s of vtData.subdomains) { const m = mergedHostEntry(s); if (m) mergedHosts.add(m); }
    for (const s of bbotData.subdomains) { const m = mergedHostEntry(s); if (m) mergedHosts.add(m); }
    if (mergedHosts.size === 0) mergedHosts.add(target);

    const ipSources: IpSourceMap = new Map();
    for (const ip of vtData.ips) addIpSource(ipSources, ip, 'virustotal');
    for (const ip of bbotData.ips) addIpSource(ipSources, ip, 'bbot');
    const hostList = Array.from(mergedHosts);
    const dnsCap = mode === 'full' ? 400 : 200;
    const dnsIps = await resolveIpsForHosts(hostList, dnsCap);
    for (const ip of dnsIps) addIpSource(ipSources, ip, 'dns');

    const ipInventory = Array.from(ipSources.keys());
    const ipMax = mode === 'full' ? 800 : 250;
    const ips = ipInventory.slice(0, ipMax);
    if (ipInventory.length > ipMax) {
      console.warn(`/api/ports: IP inventory capped ${ipMax}/${ipInventory.length} (mode=${mode})`);
    }

    // 2) TCP connect scan against each IP and selected ports (no root; avoids naabu/nmap requirements)
    const net = await import('net');
    const perSocketTimeoutMs = mode === 'full' ? 900 : 700;
    const maxConcurrent = mode === 'full' ? 260 : 140;

    async function isPortOpen(ip: string, port: number): Promise<boolean> {
      return await new Promise<boolean>((resolve) => {
        const s = new net.Socket();
        let settled = false;
        const done = (ok: boolean) => {
          if (settled) return;
          settled = true;
          try { s.destroy(); } catch {}
          resolve(ok);
        };
        s.setTimeout(perSocketTimeoutMs);
        s.once('connect', () => done(true));
        s.once('timeout', () => done(false));
        s.once('error', () => done(false));
        try {
          s.connect(port, ip);
        } catch {
          done(false);
        }
      });
    }

    type IpPort = { ip: string; port: number };
    const open: IpPort[] = [];
    const tasks: Array<() => Promise<void>> = [];
    for (const ip of ips) {
      for (const port of ports) {
        tasks.push(async () => {
          const ok = await isPortOpen(ip, port);
          if (ok) open.push({ ip, port });
        });
      }
    }

    // simple concurrency runner
    let idx = 0;
    const workers = new Array(Math.min(maxConcurrent, tasks.length)).fill(0).map(async () => {
      while (idx < tasks.length) {
        const cur = idx++;
        const fn = tasks[cur];
        if (fn) await fn();
      }
    });
    await Promise.all(workers);

    // 3) Build probe URLs:
    // - always try https://ip (and also http://ip as a fallback)
    // - for each open port: try https://ip:port and http://ip:port
    const urlSet = new Set<string>();
    for (const ip of ips) {
      urlSet.add(`https://${ip}`);
      urlSet.add(`http://${ip}`);
    }
    for (const f of open) {
      urlSet.add(`https://${f.ip}:${f.port}`);
      urlSet.add(`http://${f.ip}:${f.port}`);
    }
    const urlInputs = Array.from(urlSet);
    const urlMax = mode === 'full' ? 9000 : 3000;
    const urlSlice = urlInputs.slice(0, urlMax);
    if (urlInputs.length > urlMax) {
      console.warn(`/api/ports: httpx URL probe capped ${urlMax}/${urlInputs.length} (mode=${mode})`);
    }

    // 4) Probe URLs with httpx (status/title/tech)
    const httpxArgs = mode === 'full'
      ? ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '60', '-timeout', '10', '-retries', '2']
      : ['-silent', '-json', '-title', '-status-code', '-tech-detect', '-threads', '180', '-timeout', '5', '-retries', '1'];
    const httpx = spawn('httpx', httpxArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
    let httpxStdout = '';
    let httpxStderr = '';
    const httpxTimer = setTimeout(() => { try { httpx.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 180 : 1000 * 90);
    try {
      for (const u of urlSlice) httpx.stdin.write(u + '\n');
      httpx.stdin.end();
    } catch {}
    httpx.stdout.on('data', (chunk: Buffer) => { httpxStdout += chunk.toString(); });
    httpx.stderr.on('data', (chunk: Buffer) => { httpxStderr += chunk.toString(); });
    await new Promise<void>((resolve) => {
      httpx.on('error', () => { clearTimeout(httpxTimer); resolve(); });
      httpx.on('close', () => { clearTimeout(httpxTimer); resolve(); });
    });

    const probes: Record<string, { url: string; statusCode: number | null; title: string; technologies: string[] }> = {};
    httpxStdout.split('\n').map(l => l.trim()).filter(Boolean).forEach((line) => {
      try {
        const obj = JSON.parse(line);
        const key = String(obj.url || '');
        if (!key) return;
        probes[key] = {
          url: obj.url ?? '',
          statusCode: obj.status_code ?? obj.status ?? null,
          title: obj.title ?? '',
          technologies: obj.tech ?? obj.technologies ?? [],
        };
      } catch {}
    });
    if (httpxStderr) console.warn(`/api/ports httpx stderr: ${httpxStderr.substring(0, 200)}`);

    // 5) Shape results for the existing frontend table
    const portsByIp = new Map<string, number[]>();
    for (const f of open) {
      if (!portsByIp.has(f.ip)) portsByIp.set(f.ip, []);
      portsByIp.get(f.ip)!.push(f.port);
    }
    for (const [ip, ps] of portsByIp.entries()) {
      ps.sort((a, b) => a - b);
    }

    type Row = { url: string; host: string; statusCode: number | null; title: string; technologies: string[] };
    const results: Row[] = [];

    // per-IP summary rows
    for (const ip of ips) {
      const ps = portsByIp.get(ip) || [];
      const src = Array.from(ipSources.get(ip) || []).sort();
      results.push({
        url: `ip://${ip}`,
        host: ip,
        statusCode: null,
        title: ps.length ? `Open ports: ${ps.join(', ')}` : 'No open ports found (selected set)',
        technologies: ['port-scan', ...src],
      });
    }

    // probed URL rows (base + ip:port)
    for (const u of urlSlice) {
      const p = probes[u];
      if (!p) continue;
      let host = '';
      try { host = new URL(u).hostname; } catch { host = u; }
      const portTag = (() => {
        try {
          const uu = new URL(u);
          return uu.port ? `port:${uu.port}` : 'port:default';
        } catch {
          return 'port:unknown';
        }
      })();
      results.push({
        url: p.url || u,
        host,
        statusCode: p.statusCode,
        title: p.title || '',
        technologies: Array.from(new Set([portTag, ...(p.technologies || [])])),
      });
    }

    res.json({ target, count: results.length, results });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Port scan failed', message: err.shortMessage || err.message || String(err) });
  }

});

// ── Host-discovery enrichment helpers ─────────────────────────────────────
// These let discovered IPs and subdomains "feed each other": certs and PTR
// records on an IP reveal new hostnames; ASN/CIDR neighbours reveal new IPs;
// all of which loop back into virtual-host probing.

const resolvePtrAsync = promisify(dns.reverse);

/** Reverse-DNS (PTR) an IP → in-scope hostnames not yet known. */
async function reverseDnsHostnames(ip: string, target: string): Promise<string[]> {
  try {
    const names = await resolvePtrAsync(ip);
    const out: string[] = [];
    for (const raw of names || []) {
      const h = normalizeHostname(String(raw)).replace(/\.$/, '');
      if (isValidDomain(h) && isUnderTarget(h, target)) out.push(h);
    }
    return Array.from(new Set(out));
  } catch {
    return [];
  }
}

/** Pull the TLS cert from ip:443 and return in-scope hostnames from CN + SAN. */
function harvestCertSans(ip: string, target: string, timeoutMs = 6000): Promise<string[]> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: string[]) => { if (!settled) { settled = true; resolve(v); } };
    try {
      // No `servername` here: we want the IP's *default* cert, which often
      // lists every vhost it terminates TLS for.
      const socket = tls.connect({ host: ip, port: 443, rejectUnauthorized: false, timeout: timeoutMs }, () => {
        const cert = socket.getPeerCertificate(true);
        const names = new Set<string>();
        try {
          if (cert && Object.keys(cert).length > 0) {
            const cn = cert.subject?.CN;
            if (cn) names.add(String(cn));
            if (cert.subjectaltname) {
              for (const part of cert.subjectaltname.split(',')) {
                const m = part.trim().replace(/^DNS:/i, '');
                if (m) names.add(m);
              }
            }
          }
        } catch {}
        socket.destroy();
        const out: string[] = [];
        for (const n of names) {
          const h = normalizeHostname(n).replace(/^\*\./, '');
          if (isValidDomain(h) && isUnderTarget(h, target)) out.push(h);
        }
        done(Array.from(new Set(out)));
      });
      socket.on('error', () => { try { socket.destroy(); } catch {}; done([]); });
      socket.on('timeout', () => { try { socket.destroy(); } catch {}; done([]); });
    } catch {
      done([]);
    }
  });
}

const ipv4OnlyRe = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
function ipv4ToInt(ip: string): number | null {
  const m = ipv4OnlyRe.exec(ip);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map((p) => parseInt(p as string, 10));
  if (parts.some((n) => !(n >= 0 && n <= 255))) return null;
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!;
}
function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

type AsnInfo = { prefix: string; asn: number | null; name: string | null };
/** Look up the announced prefix/ASN for an IP via the free bgpview API. */
async function fetchAsnInfo(ip: string): Promise<AsnInfo | null> {
  if (!ipv4OnlyRe.test(ip)) return null;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 8000);
  try {
    const res = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, { signal: ac.signal });
    if (!res.ok) return null;
    const j: any = await res.json();
    const pfx = j?.data?.prefixes?.[0];
    if (!pfx?.prefix) return null;
    return {
      prefix: String(pfx.prefix),
      asn: pfx?.asn?.asn ?? null,
      name: pfx?.asn?.name ?? pfx?.asn?.description ?? null,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Expand an IPv4 CIDR into individual host IPs, capped, excluding seeds. */
function expandCidrNeighbours(cidr: string, cap: number, exclude: Set<string>): string[] {
  const [base, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr || '', 10);
  const baseInt = base ? ipv4ToInt(base) : null;
  if (baseInt === null || !Number.isFinite(bits) || bits < 0 || bits > 32) return [];
  // Refuse to expand very large prefixes (too noisy / slow); cap handles the rest.
  const size = bits >= 32 ? 1 : 2 ** (32 - bits);
  if (size > 65536) return [];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const out: string[] = [];
  for (let i = 0; i < size && out.length < cap; i++) {
    const ipInt = (network + i) >>> 0;
    const ip = intToIpv4(ipInt);
    if (!exclude.has(ip)) out.push(ip);
  }
  return out;
}

/** Quick TCP liveness probe (no Host header) on 443 then 80. */
function ipIsLive(ip: string, timeoutMs = 3000): Promise<boolean> {
  const tryPort = (port: number) => new Promise<boolean>((resolve) => {
    let settled = false;
    const done = (v: boolean) => { if (!settled) { settled = true; resolve(v); } };
    try {
      const socket = require('net').connect({ host: ip, port, timeout: timeoutMs }, () => { socket.destroy(); done(true); });
      socket.on('error', () => { try { socket.destroy(); } catch {}; done(false); });
      socket.on('timeout', () => { try { socket.destroy(); } catch {}; done(false); });
    } catch { done(false); }
  });
  return tryPort(443).then((ok) => (ok ? true : tryPort(80)));
}

// POST /api/host-discovery { target, mode? }
app.post('/api/host-discovery', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const mode = parse.data.mode || 'fast';

  try {
    const ffufMatchCodes = process.env.FFUF_MATCH_CODES?.trim()
      ? process.env.FFUF_MATCH_CODES.trim()
      : '200,204,301,302,307,401,403,405,500';

    const ffufTimeoutSeconds = Number.parseInt(process.env.FFUF_TIMEOUT_SECONDS || '', 10);
    const ffufTimeout = Number.isFinite(ffufTimeoutSeconds) && ffufTimeoutSeconds > 0 ? ffufTimeoutSeconds : 10;

    const ffufThreadsEnv = Number.parseInt(process.env.FFUF_THREADS || '', 10);
    const ffufThreads = Number.isFinite(ffufThreadsEnv) && ffufThreadsEnv > 0 ? ffufThreadsEnv : 40;

    const wordlistMaxEnv = Number.parseInt(process.env.HOST_DISCOVERY_WORDLIST_MAX || '', 10);
    const wordlistMax = Number.isFinite(wordlistMaxEnv) && wordlistMaxEnv > 0
      ? wordlistMaxEnv
      : mode === 'full'
        ? 8000
        : 2000;

    const ipMaxEnv = Number.parseInt(process.env.HOST_DISCOVERY_IP_MAX || '', 10);
    const ipMax = Number.isFinite(ipMaxEnv) && ipMaxEnv > 0
      ? ipMaxEnv
      : mode === 'full'
        ? 500
        : 150;

    // 1) Build merged hostname inventory (same sources as /api/recon)
    let subdomains: string[] = [];
    let subfinderStdout = '';
    let subfinderStderr = '';
    let subfinderHostCount = 0;

    try {
      const subfinderArgs = mode === 'full'
        ? ['-silent', '-all', '-d', target]
        : ['-silent', '-d', target];

      const subfinder = spawn('subfinder', subfinderArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
      const subfinderTimer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, mode === 'full' ? 1000 * 90 : 1000 * 60);
      subfinder.stdout.on('data', (chunk: Buffer) => { subfinderStdout += chunk.toString(); });
      subfinder.stderr.on('data', (chunk: Buffer) => { subfinderStderr += chunk.toString(); });

      await new Promise<void>((resolve) => {
        subfinder.on('error', (err) => {
          console.error(`subfinder spawn error for ${target}:`, err);
          clearTimeout(subfinderTimer);
          resolve();
        });
        subfinder.on('close', (code) => {
          clearTimeout(subfinderTimer);
          if (code === 0 || code === null) {
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n')
                .map(l => l.trim())
                .filter(Boolean)
                .filter(isValidDomain)
            ));
          } else {
            console.warn(`subfinder exited with code ${code} for ${target}: ${subfinderStderr || 'no stderr'}`);
            subdomains = Array.from(new Set(
              subfinderStdout.split('\n')
                .map(l => l.trim())
                .filter(Boolean)
                .filter(isValidDomain)
            ));
          }
          subfinderHostCount = subdomains.length;
          resolve();
        });
      });
    } catch {
      // Keep empty; downstream will fallback to base domain
    }

    function mergedHostEntry(raw: string): string | null {
      const h = normalizeHostname(raw).replace(/^\*\./, '');
      if (!isUnderTarget(h, target)) return null;
      if (!isValidDomain(h)) return null;
      return h;
    }

    // Fetch extra sources in parallel
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    const bbotBase = process.env.BBOT_OUTPUT_DIR || path.join(process.cwd(), 'bbot-output');
    const safeTargetDir = target.replace(/[^a-z0-9.-]/gi, '_');
    const explicitBbot = process.env.BBOT_SCAN_PATH?.trim();
    const bbotDir =
      explicitBbot && existsSync(explicitBbot)
        ? explicitBbot
        : path.join(bbotBase, safeTargetDir);

    const [crtNames, vtData, bbotData] = await Promise.all([
      fetchCrtShHostnames(target),
      fetchVirusTotalDomain(target, vtKey),
      Promise.resolve(parseBbotOutputDirectory(bbotDir, target)),
    ]);

    const mergedSubs = new Set<string>();
    for (const s of subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of crtNames) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of vtData.subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }
    for (const s of bbotData.subdomains) {
      const m = mergedHostEntry(s);
      if (m) mergedSubs.add(m);
    }

    subdomains = Array.from(mergedSubs);
    if (subdomains.length === 0) {
      subdomains = [target];
    }

    // 2) Build IP inventory: passive IPs from VT/BBot + DNS resolution from merged hosts
    const ipSources: IpSourceMap = new Map();
    for (const ip of vtData.ips) addIpSource(ipSources, ip, 'virustotal');
    for (const ip of bbotData.ips) addIpSource(ipSources, ip, 'bbot');

    const dnsCap = mode === 'full' ? 150 : 80;
    const dnsIps = await resolveIpsForHosts(subdomains, dnsCap);
    for (const ip of dnsIps) addIpSource(ipSources, ip, 'dns');

    const ipInventory = Array.from(ipSources.keys()).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    const ips = ipInventory.slice(0, ipMax);

    // 3) Sort merged subdomains
    const mergedSubdomainsSorted = [...subdomains].sort((a, b) => a.localeCompare(b));
    if (mergedSubdomainsSorted.length === 0 || ips.length === 0) {
      return res.json({
        target,
        count: 0,
        results: [],
        ipDiscoveryCount: 0,
        subdomainDiscoveryCount: 0,
        unreachableSubdomainCount: 0,
        mergedCount: subdomains.length,
        ipCount: ips.length,
        ipResults: ipMapToRows(ipSources),
        discovery: {
          subfinder: subfinderHostCount,
          crtSh: crtNames.length,
          virusTotal: { hosts: vtData.subdomains.length, ips: vtData.ips.length },
          bbot: { hosts: bbotData.subdomains.length, ips: bbotData.ips.length },
          bbotDir,
          outputFile: null,
        },
      });
    }

    type HostDiscoveryRow = {
      ip: string; url: string; host: string; statusCode: number | null;
      title: string; technologies: string[]; size: number | null;
      words: number | null; lines: number | null; durationMs: number | null;
      confidence: 'high' | 'medium' | 'low'; matchReason: string;
      phase: 'ip' | 'subdomain';
    }
    const UNREACHABLE_CODES = new Set([404, 403, 501, 503]);

    const ipCap = mode === 'full' ? 30 : 15;
    let cappedIps = ips.slice(0, ipCap);
    const subCap = mode === 'full' ? 300 : 100;
    let cappedSubs = mergedSubdomainsSorted.slice(0, subCap);

    // ── Enrichment: make IPs and subdomains feed each other ──────────────────
    // (a) PTR + TLS-cert SAN harvesting on each seed IP → new in-scope hostnames
    // (b) ASN/CIDR neighbour expansion (full mode) → new live IPs
    const enrich = {
      ptrHosts: [] as string[],
      certHosts: [] as string[],
      neighbourIps: [] as string[],
      asn: null as AsnInfo | null,
    };
    try {
      const ptrCertPairs = await Promise.all(
        cappedIps.map(async (ip) => {
          const [ptr, cert] = await Promise.all([
            reverseDnsHostnames(ip, target),
            harvestCertSans(ip, target),
          ]);
          return { ip, ptr, cert };
        })
      );
      const newHostSet = new Set<string>();
      for (const { ptr, cert } of ptrCertPairs) {
        for (const h of ptr) { enrich.ptrHosts.push(h); newHostSet.add(h); }
        for (const h of cert) { enrich.certHosts.push(h); newHostSet.add(h); }
      }
      enrich.ptrHosts = Array.from(new Set(enrich.ptrHosts)).sort();
      enrich.certHosts = Array.from(new Set(enrich.certHosts)).sort();

      // Fold newly discovered hostnames into the merged inventory + probe set
      for (const h of newHostSet) {
        if (!subdomains.includes(h)) subdomains.push(h);
        if (!cappedSubs.includes(h)) cappedSubs.push(h);
      }
      cappedSubs = cappedSubs.slice(0, subCap + 200); // allow a little headroom for enriched hosts

      // (b) ASN/CIDR neighbour expansion — only in full mode (it's noisier/slower)
      if (mode === 'full') {
        const neighbourCapEnv = Number.parseInt(process.env.HOST_DISCOVERY_CIDR_NEIGHBOURS || '', 10);
        const neighbourCap = Number.isFinite(neighbourCapEnv) && neighbourCapEnv >= 0 ? neighbourCapEnv : 64;
        if (neighbourCap > 0) {
          const seenIps = new Set(cappedIps);
          const v4Seeds = cappedIps.filter((ip) => ipv4OnlyRe.test(ip)).slice(0, 5); // bound API calls
          const liveNeighbours = new Set<string>();
          for (const seed of v4Seeds) {
            const asn = await fetchAsnInfo(seed);
            if (!asn) continue;
            if (!enrich.asn) enrich.asn = asn;
            const candidates = expandCidrNeighbours(asn.prefix, neighbourCap, seenIps).slice(0, neighbourCap);
            // Liveness-probe candidates with bounded concurrency
            const NEIGH_CONC = 40;
            let nIdx = 0;
            await Promise.all(Array.from({ length: Math.min(NEIGH_CONC, candidates.length || 1) }, async () => {
              while (nIdx < candidates.length) {
                const cand = candidates[nIdx++];
                if (!cand) continue;
                if (await ipIsLive(cand)) liveNeighbours.add(cand);
              }
            }));
            if (liveNeighbours.size >= neighbourCap) break;
          }
          enrich.neighbourIps = Array.from(liveNeighbours).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
          for (const ip of enrich.neighbourIps) {
            addIpSource(ipSources, ip, 'asn-neighbour');
            if (!cappedIps.includes(ip)) cappedIps.push(ip);
          }
          cappedIps = cappedIps.slice(0, ipCap + neighbourCap);
        }
      }
    } catch (enrichErr) {
      console.warn('[host-discovery] enrichment error:', enrichErr);
    }

    console.log(
      `[host-discovery] probing ${cappedIps.length} IPs x ${cappedSubs.length} subdomains ` +
      `(enrich: +${enrich.ptrHosts.length} PTR, +${enrich.certHosts.length} cert, +${enrich.neighbourIps.length} neighbour IPs)`
    );

    // Pure Node HTTPS prober — sends one request per (ip, host) pair with a custom Host header.
    // No external tools, no EPIPE, no arg-length limits.
    const https = await import('https');
    const http = await import('http');

    interface ProbeResult {
      ip: string; host: string; port: number; proto: 'https' | 'http';
      statusCode: number | null; title: string; size: number | null; bodyLen: number;
      location: string | null; durationMs: number;
    }
    // Signature used for baseline (default-vhost) comparison. Two responses
    // that share status + body size + title + redirect target are treated as
    // the same catch-all page. The redirect Location is normalized so that a
    // server echoing the requested host (e.g. http→https of the same host)
    // doesn't make every vhost look "different" from the baseline.
    const sigOf = (r: ProbeResult): string => {
      let loc = r.location ?? '';
      if (loc && r.host) loc = loc.split(r.host).join('%HOST%');
      return `${r.statusCode}|${r.size ?? r.bodyLen}|${r.title}|${loc}`;
    };

    function probeOne(ip: string, host: string, port: number, proto: 'https' | 'http'): Promise<ProbeResult | null> {
      return new Promise((resolve) => {
        const t0 = Date.now();
        const options: any = {
          hostname: ip,
          port,
          path: '/',
          method: 'GET',
          headers: { 'Host': host, 'User-Agent': 'Mozilla/5.0 recon-app' },
          timeout: 6000,
          rejectUnauthorized: false,
        };
        // For HTTPS, also set SNI so we catch servers that route on TLS
        // servername rather than the HTTP Host header. `host` here is the
        // candidate vhost (or the bogus baseline host).
        if (proto === 'https' && !isIPAddress(host)) {
          options.servername = host;
        }
        const mod = proto === 'https' ? https : http;
        let settled = false;
        const done = (r: ProbeResult | null) => { if (!settled) { settled = true; resolve(r); } };
        try {
          const req = (mod as any).request(options, (res: any) => {
            const statusCode = res.statusCode ?? null;
            const location = typeof res.headers['location'] === 'string' ? res.headers['location'] : null;
            let body = '';
            let bodyLen = 0;
            res.on('data', (c: Buffer) => { bodyLen += c.length; if (body.length < 4096) body += c.toString(); });
            res.on('end', () => {
              const titleMatch = body.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
              const title = titleMatch?.[1]?.trim() ?? '';
              done({ ip, host, port, proto, statusCode, title, size: parseInt(res.headers['content-length'] ?? '', 10) || null, bodyLen, location, durationMs: Date.now() - t0 });
            });
            res.on('error', () => done(null));
          });
          req.on('timeout', () => { req.destroy(); done(null); });
          req.on('error', () => done(null));
          req.end();
        } catch { done(null); }
      });
    }

    const CONCURRENCY = 80;
    const PORT_PROTOS: [number, 'https' | 'http'][] = [[443, 'https'], [80, 'http']];

    // ── Baseline: capture each IP's default-vhost response with a bogus Host ──
    // Anything that later matches this signature is just the catch-all page and
    // is discarded as a false positive.
    const baselineSig = new Map<string, string | null>(); // `${ip}|${port}|${proto}` -> sig|null
    const bogusHost = `nonexistent-${randomUUID().slice(0, 8)}.${target}`;
    const baseTasks: Array<() => Promise<void>> = [];
    for (const ip of cappedIps) {
      for (const [port, proto] of PORT_PROTOS) {
        baseTasks.push(async () => {
          const r = await probeOne(ip, bogusHost, port, proto);
          baselineSig.set(`${ip}|${port}|${proto}`, r && r.statusCode !== null ? sigOf(r) : null);
        });
      }
    }
    let bIdx = 0;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, baseTasks.length || 1) }, async () => {
      while (bIdx < baseTasks.length) { const fn = baseTasks[bIdx++]; if (fn) await fn(); }
    }));

    // Decide whether a probe result is a genuine vhost hit vs the catch-all.
    function classifyHit(r: ProbeResult): { keep: boolean; confidence: 'high' | 'medium' | 'low'; reason: string } {
      const base = baselineSig.get(`${r.ip}|${r.port}|${r.proto}`);
      const sig = sigOf(r);
      if (base === null || base === undefined) {
        // Baseline got nothing back → a concrete response here is meaningful.
        return { keep: true, confidence: 'high', reason: 'no-default-vhost' };
      }
      if (sig === base) {
        return { keep: false, confidence: 'low', reason: 'matches-default-vhost' };
      }
      return { keep: true, confidence: r.title ? 'high' : 'medium', reason: 'differs-from-default' };
    }

    // ── Phase 1: IP → subdomain (which of our hosts does this IP serve?) ─────
    const ipTasks: Array<() => Promise<void>> = [];
    const ipDiscoveryResults: HostDiscoveryRow[] = [];
    for (const ip of cappedIps) {
      for (const sub of cappedSubs) {
        for (const [port, proto] of PORT_PROTOS) {
          ipTasks.push(async () => {
            const r = await probeOne(ip, sub, port, proto);
            if (r && r.statusCode !== null) {
              const cls = classifyHit(r);
              if (!cls.keep) return;
              ipDiscoveryResults.push({
                ip, url: `${proto}://${ip}:${port}`, host: sub,
                statusCode: r.statusCode, title: r.title,
                technologies: [], size: r.size, words: null, lines: null, durationMs: r.durationMs,
                confidence: cls.confidence, matchReason: cls.reason, phase: 'ip',
              });
            }
          });
        }
      }
    }

    let taskIdx = 0;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ipTasks.length) }, async () => {
      while (taskIdx < ipTasks.length) {
        const fn = ipTasks[taskIdx++];
        if (fn) await fn();
      }
    }));

    console.log(`[host-discovery] Phase 1 done: ${ipDiscoveryResults.length} hits`);

    // ── Phase 2: Subdomain → IP (reverse) ───────────────────────────────────
    // Direct-probe each subdomain normally to find unreachable ones
    const directResults = new Map<string, number | null>();
    const directTasks: Array<() => Promise<void>> = [];
    for (const sub of cappedSubs) {
      directTasks.push(async () => {
        const r = await probeOne(sub, sub, 443, 'https') ?? await probeOne(sub, sub, 80, 'http');
        directResults.set(sub, r?.statusCode ?? null);
      });
    }
    let dIdx = 0;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, directTasks.length) }, async () => {
      while (dIdx < directTasks.length) { const fn = directTasks[dIdx++]; if (fn) await fn(); }
    }));

    const reachableHosts = new Set(
      ipDiscoveryResults.filter(r => r.statusCode !== null && !UNREACHABLE_CODES.has(r.statusCode)).map(r => r.host)
    );
    const unreachableSubdomains = cappedSubs.filter(sub => {
      if (reachableHosts.has(sub)) return false;
      const code = directResults.get(sub);
      return code === undefined || code === null || UNREACHABLE_CODES.has(code);
    });

    console.log(`[host-discovery] Phase 2: ${unreachableSubdomains.length} unreachable subs x ${cappedIps.length} IPs`);

    type SubdomainDiscoveryRow = HostDiscoveryRow & { probeIp: string };
    const subdomainDiscoveryResults: SubdomainDiscoveryRow[] = [];
    const subTasks: Array<() => Promise<void>> = [];
    for (const sub of unreachableSubdomains) {
      for (const ip of cappedIps) {
        for (const [port, proto] of PORT_PROTOS) {
          subTasks.push(async () => {
            const r = await probeOne(ip, sub, port, proto);
            if (r && r.statusCode !== null) {
              const cls = classifyHit(r);
              if (!cls.keep) return;
              subdomainDiscoveryResults.push({
                ip, url: `${proto}://${ip}:${port}`, host: sub,
                statusCode: r.statusCode, title: r.title,
                technologies: [], size: r.size, words: null, lines: null, durationMs: r.durationMs,
                confidence: cls.confidence, matchReason: cls.reason, phase: 'subdomain',
                probeIp: ip,
              });
            }
          });
        }
      }
    }
    let sIdx = 0;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, subTasks.length || 1) }, async () => {
      while (sIdx < subTasks.length) { const fn = subTasks[sIdx++]; if (fn) await fn(); }
    }));

    console.log(`[host-discovery] Phase 2 done: ${subdomainDiscoveryResults.length} hits`);

    // ── Dedupe + confidence ranking ──────────────────────────────────────────
    // Collapse identical (ip, url, host, status) rows and keep the highest
    // confidence seen. Sort high→low confidence so real findings surface first.
    const confRank: Record<string, number> = { high: 3, medium: 2, low: 1 };
    const dedupeMap = new Map<string, HostDiscoveryRow>();
    for (const row of [...ipDiscoveryResults, ...subdomainDiscoveryResults]) {
      const key = `${row.ip}|${row.url}|${row.host}|${row.statusCode}`;
      const existing = dedupeMap.get(key);
      if (!existing || (confRank[row.confidence] ?? 0) > (confRank[existing.confidence] ?? 0)) {
        dedupeMap.set(key, row);
      }
    }
    const allResults = Array.from(dedupeMap.values()).sort((a, b) => {
      const cr = (confRank[b.confidence] ?? 0) - (confRank[a.confidence] ?? 0);
      if (cr !== 0) return cr;
      return a.host.localeCompare(b.host);
    });

    // Live hostnames = distinct hosts that produced a kept (non-default) hit.
    const liveHosts = Array.from(new Set(allResults.map(r => r.host))).sort();
    // Live IPs = distinct IPs that served at least one kept vhost.
    const liveIps = Array.from(new Set(allResults.map(r => r.ip)))
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

    res.json({
      target,
      count: allResults.length,
      results: allResults,
      ipDiscoveryCount: allResults.filter(r => r.phase === 'ip').length,
      subdomainDiscoveryCount: allResults.filter(r => r.phase === 'subdomain').length,
      unreachableSubdomainCount: unreachableSubdomains.length,
      mergedCount: subdomains.length,
      ipCount: ips.length,
      ipResults: ipMapToRows(ipSources),
      // New: live cross-referenced inventory + enrichment provenance
      liveHosts,
      liveIps,
      liveHostCount: liveHosts.length,
      liveIpCount: liveIps.length,
      confidenceBreakdown: {
        high: allResults.filter(r => r.confidence === 'high').length,
        medium: allResults.filter(r => r.confidence === 'medium').length,
        low: allResults.filter(r => r.confidence === 'low').length,
      },
      enrichment: {
        ptrHosts: enrich.ptrHosts,
        certHosts: enrich.certHosts,
        neighbourIps: enrich.neighbourIps,
        asn: enrich.asn,
      },
      discovery: {
        subfinder: subfinderHostCount,
        crtSh: crtNames.length,
        virusTotal: { hosts: vtData.subdomains.length, ips: vtData.ips.length },
        bbot: { hosts: bbotData.subdomains.length, ips: bbotData.ips.length },
        ptr: enrich.ptrHosts.length,
        certSan: enrich.certHosts.length,
        asnNeighbours: enrich.neighbourIps.length,
        bbotDir,
        outputFile: null,
      },
    });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Host discovery failed', message: err.shortMessage || err.message || String(err) });
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

  // limits to keep runtime sane while still scanning a broad set of subdomains
  const maxHosts = mode === 'full' ? 300 : 120;
  // Allow more time per host so nmap can complete service detection and scripts
  const nmapTimeoutMs = mode === 'full' ? 1000 * 300 : 1000 * 60;
  // Centralized port selection for nmap vuln scanning (covers common web + ssh/ftp/mysql)
  const nmapPorts = '21,22,80,443,8080,8000,8443,3306';

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
        sfOut.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)
      ));
    } catch (sfErr: any) {
      console.error(`subfinder failed for ${target}, using base domain only:`, sfErr.message || sfErr);
    }
    
    // Fallback to base domain if subfinder found nothing
    if (hosts.length === 0) {
      hosts = [target];
      console.log(`No subdomains found for ${target}, using base domain`);
    }

    // 2) scan by hostname directly to preserve SNI; skip A record resolution here

    // Truncate hosts if subfinder returned too many to keep scan time reasonable
    const hostLimitHit = hosts.length > maxHosts;
    if (hostLimitHit) {
      hosts = hosts.slice(0, maxHosts);
    }

    // 3) run nmap -sV against selected ports with vulners script
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
        const args = ['-Pn', '-T4', '-sV', '-p', nmapPorts, '--open', '--script', 'vulners', host];
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
    res.json({ target, count: tableResults.length, results: tableResults, hostLimitHit });
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
        subfinderStdout.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)
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

// POST /api/urls-prefetch { target, subdomains[] }
// Fire-and-forget: called by frontend after recon completes to warm the Wayback cache.
app.post('/api/urls-prefetch', reconLimiter, (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: 'Invalid payload' });
  const { target } = parse.data;

  const rawSubs: unknown = req.body.subdomains;
  const subdomains: string[] = Array.isArray(rawSubs)
    ? (rawSubs as string[]).filter((s): s is string => typeof s === 'string' && isValidDomain(s)).slice(0, 300)
    : [target];

  const existing = getOrLoadWaybackCache(target);
  if (existing) {
    return res.json({ status: existing.status, cached: existing.results.size });
  }

  runWaybackPrefetch(target, subdomains).catch(() => {});
  res.json({ status: 'started', subdomains: subdomains.length });
});

// POST /api/urls-scan — streaming NDJSON
// Accepts { target, subdomains: string[] } — subdomains are the live-200 hosts from recon.
// Streams one JSON line per subdomain as it completes so the frontend renders progressively.
app.post('/api/urls-scan', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;

  // Accept live subdomains passed from the frontend (200-status hosts from recon)
  const rawSubs: unknown = req.body.subdomains;
  let subdomains: string[] = Array.isArray(rawSubs)
    ? (rawSubs as string[]).filter((s): s is string => typeof s === 'string' && isValidDomain(s))
    : [];

  // Fallback: use prefetch cache keys or base domain
  if (subdomains.length === 0) {
    const prefetched = getOrLoadWaybackCache(target);
    subdomains = prefetched && prefetched.results.size > 0
      ? Array.from(prefetched.results.keys())
      : [target];
  }

  console.log(`[urls-scan] ${target}: scanning ${subdomains.length} subdomains via Wayback`);

  // Streaming NDJSON — one JSON line per subdomain result
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  res.write(JSON.stringify({ type: 'start', target, total: subdomains.length }) + '\n');

  const waybackEntry = getOrLoadWaybackCache(target);
  const cachedResults = waybackEntry?.results ?? new Map<string, string[]>();

  let totalUrls = 0;
  const seenUrls = new Set<string>();

  // 4 concurrent — polite to Wayback, avoids 429s
  const CONCURRENCY = 4;
  for (let i = 0; i < subdomains.length; i += CONCURRENCY) {
    const batch = subdomains.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(async (subdomain) => {
      let urls: string[];
      if (cachedResults.has(subdomain)) {
        urls = cachedResults.get(subdomain)!;
      } else {
        const result = await fetchWaybackForSubdomain(subdomain);
        urls = result.urls;
        if (urls.length > 0 && waybackEntry) {
          waybackEntry.results.set(subdomain, urls);
        }
      }

      const uniqueUrls = urls.filter(u => {
        if (seenUrls.has(u)) return false;
        seenUrls.add(u);
        return true;
      });
      totalUrls += uniqueUrls.length;

      try {
        res.write(JSON.stringify({ type: 'subdomain', subdomain, urlCount: uniqueUrls.length, urls: uniqueUrls }) + '\n');
      } catch {}
    }));
  }

  if (waybackEntry) saveWaybackCacheToDisk(target, waybackEntry);

  try {
    res.write(JSON.stringify({ type: 'done', target, totalSubdomains: subdomains.length, totalUrls }) + '\n');
    res.end();
  } catch {}
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

      subdomains = Array.from(new Set(
        sfOut.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)
      )).slice(0, mode === 'full' ? 150 : 60);
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
      // Only add valid domains to avoid "Invalid URL" errors
      if (isValidDomain(h) && hostnameRegex.test(h)) {
        urls.push(`https://${h}`);
        urls.push(`http://${h}`);
      }
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
        // Validate URL before processing
        let urlObj: URL;
        try {
          urlObj = new URL(u);
        } catch (urlErr) {
          console.warn(`Invalid URL skipped in headers-check: ${u}`);
          continue; // Skip invalid URLs
        }
        
        const r = await fetchWithTimeout(u);
        const lc = new Map<string, string>();
        r.headers.forEach((v, k) => lc.set(k.toLowerCase(), v));
        const missing = checks.filter(h => !lc.has(h));
        const present = checks.filter(h => lc.has(h)).map(h => `${h}:present`);
        const title = `${missing.length === 0 ? 'All headers present' : `Missing: ${missing.join(', ')}`}`;
        results.push({ url: u, host: urlObj.hostname, statusCode: r.status, title, technologies: present });
      } catch (e: any) {
        // Try to extract hostname safely
        let hostname = 'unknown';
        try {
          hostname = new URL(u).hostname;
        } catch {}
        results.push({ url: u, host: hostname, statusCode: null, title: `Error: ${(e && (e.message || String(e))) || 'request failed'}`, technologies: [] });
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
      const subs = Array.from(new Set(
        sfOut.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)
      )).slice(0, 50);
      for (const s of subs) {
        const h = s.replace(/^\*\.?/, '').replace(/^www\./, '');
        if (isValidDomain(h)) {
          nameCandidatesSet.add(h);
          nameCandidatesSet.add(h.replace(/\./g, '-'));
          nameCandidatesSet.add(h.split('.').join(''));
        }
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

// Helper function to convert HTTP config object to YAML
function generateYamlFromConfig(config: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  json?: Record<string, any>;
  body?: string;
  payloadPlaceholder?: string;
  payloadEncoding?: string;
  answerFocusHint?: string;
  verifySsl?: boolean;
  proxy?: { scheme: string; host: string; port: number; username?: string; password?: string };
}): string {
  const lines: string[] = [];
  lines.push('name: Auto-generated Config');
  lines.push(`method: ${config.method || 'POST'}`);
  lines.push(`url: ${config.url}`);
  
  if (config.headers && Object.keys(config.headers).length > 0) {
    lines.push('headers:');
    for (const [key, value] of Object.entries(config.headers)) {
      lines.push(`  ${key}: ${value}`);
    }
  }
  
  if (config.json) {
    lines.push('json:');
    const jsonStr = JSON.stringify(config.json, null, 2);
    // Replace payload placeholder in JSON string
    const replacedJson = jsonStr.replace(/"\{PAYLOAD_POSITION\}"/g, '"{PAYLOAD_POSITION}"');
    const jsonLines = replacedJson.split('\n');
    for (const line of jsonLines) {
      lines.push(`  ${line}`);
    }
  } else if (config.body) {
    if (config.payloadEncoding === 'form') {
      lines.push('payload_encoding: form');
    } else if (config.payloadEncoding === 'url') {
      lines.push('payload_encoding: url');
    }
    lines.push(`body: "${config.body.replace(/"/g, '\\"')}"`);
  }
  
  if (config.answerFocusHint) {
    lines.push(`answer_focus_hint: ${JSON.stringify(config.answerFocusHint)}`);
  }
  
  if (config.verifySsl !== undefined) {
    lines.push(`verify_ssl: ${config.verifySsl}`);
  }
  
  if (config.proxy) {
    lines.push('proxy:');
    lines.push(`  scheme: ${config.proxy.scheme}`);
    lines.push(`  host: ${config.proxy.host}`);
    lines.push(`  port: ${config.proxy.port}`);
    if (config.proxy.username) {
      lines.push(`  username: ${config.proxy.username}`);
    }
    if (config.proxy.password) {
      lines.push(`  password: ${config.proxy.password}`);
    }
  }
  
  return lines.join('\n');
}

// Helper function to recursively replace {PAYLOAD_POSITION} in JSON objects
function injectPayloadPlaceholder(obj: any, placeholder: string = '{PAYLOAD_POSITION}'): any {
  if (typeof obj === 'string') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(item => injectPayloadPlaceholder(item, placeholder));
  }
  if (obj && typeof obj === 'object') {
    const result: any = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string' && value.includes('{PAYLOAD}')) {
        result[key] = value.replace('{PAYLOAD}', placeholder);
      } else {
        result[key] = injectPayloadPlaceholder(value, placeholder);
      }
    }
    return result;
  }
  return obj;
}

// POST /api/prompt-injection { target, httpConfig?, httpConfigYaml?, ... }
app.post('/api/prompt-injection', reconLimiter, async (req, res) => {
  const parse = PromptInjectionQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  
  const {
    target,
    httpConfigYaml,
    controllerModel,
    controllerModelType,
    iterations,
    rules,
    ruleTypes,
    firewall,
    passCondition,
  } = parse.data;


  // Check if promptmap is available
  // Try multiple possible paths
  const possiblePaths = [
    process.env.PROMPTMAP_PATH,
    path.resolve(__dirname, '../tools/promptmap/promptmap2.py'), // From dist/ -> backend/tools/
    path.resolve(__dirname, '../../tools/promptmap/promptmap2.py'), // From src/ -> backend/tools/ (when running from src)
    path.resolve(process.cwd(), 'tools/promptmap/promptmap2.py'), // From backend/ directory
    path.resolve(process.cwd(), 'backend/tools/promptmap/promptmap2.py'), // From project root
    path.resolve(process.cwd(), '../backend/tools/promptmap/promptmap2.py'), // Alternative
  ].filter(Boolean) as string[];
  
  let promptmapPath: string | null = null;
  for (const p of possiblePaths) {
    if (p && existsSync(p)) {
      promptmapPath = p;
      break;
    }
  }
  
  if (!promptmapPath) {
    return res.status(500).json({ 
      error: 'promptmap not found', 
      message: `promptmap2.py not found. Tried: ${possiblePaths.join(', ')}. Please run ./setup-promptmap.sh to install promptmap or set PROMPTMAP_PATH environment variable.` 
    });
  }

  // Check for controller LLM API key
  if (controllerModelType === 'openai' && !process.env.OPENAI_API_KEY) {
    return res.status(400).json({ error: 'OPENAI_API_KEY environment variable is required for OpenAI controller model' });
  }
  if (controllerModelType === 'anthropic' && !process.env.ANTHROPIC_API_KEY) {
    return res.status(400).json({ error: 'ANTHROPIC_API_KEY environment variable is required for Anthropic controller model' });
  }

  const tempDir = path.resolve(__dirname, '../../tmp');
  try {
    if (!existsSync(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }
  } catch (e) {
    console.error('Failed to create temp directory:', e);
  }

  const configId = randomUUID();
  const configPath = path.join(tempDir, `promptmap-config-${configId}.yaml`);
  const outputPath = path.join(tempDir, `promptmap-results-${configId}.json`);

  try {
    // Use provided YAML config (YAML only mode)
    if (!httpConfigYaml || !httpConfigYaml.trim()) {
      return res.status(400).json({ error: 'YAML configuration is required' });
    }
    
    let yamlContent = httpConfigYaml.trim();
    
    // Basic YAML validation - check for common issues
    // Remove any cookie/session strings that might have been accidentally pasted
    const lines = yamlContent.split('\n');
    const cleanedLines: string[] = [];
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Skip lines that look like cookies/session strings (contain = and ; or long base64-like strings)
      // Also skip lines that are just cookie values without proper YAML structure
      if (trimmedLine.includes('cf_clearance=') || 
          trimmedLine.includes('session=') ||
          (trimmedLine.includes('=') && trimmedLine.includes(';') && trimmedLine.length > 100 && !trimmedLine.includes(':')) ||
          (trimmedLine.match(/^[a-zA-Z0-9_\-]+=[^:]+;/) && !trimmedLine.includes(':'))) {
        console.warn(`[Prompt Injection] Skipping non-YAML line: ${trimmedLine.substring(0, 50)}...`);
        continue;
      }
      
      // Keep all other lines (including empty lines for YAML structure)
      cleanedLines.push(line);
    }
    
    yamlContent = cleanedLines.join('\n').trim();
    
    if (!yamlContent.trim()) {
      return res.status(400).json({ 
        error: 'Invalid YAML configuration', 
        message: 'YAML appears to be empty or contains only invalid content. Please check your YAML format.' 
      });
    }
    
    // Validate basic YAML structure - must have url field
    if (!yamlContent.includes('url:') && !yamlContent.includes('url:')) {
      return res.status(400).json({ 
        error: 'Invalid YAML configuration', 
        message: 'YAML must contain a "url:" field. Example:\nname: Test\nmethod: POST\nurl: https://example.com/api/chat\njson:\n  message: "{PAYLOAD_POSITION}"' 
      });
    }

    // Write YAML config file
    writeFileSync(configPath, yamlContent, 'utf8');
    console.log(`[Prompt Injection] Config written to: ${configPath}`);
    console.log(`[Prompt Injection] Config preview: ${yamlContent.substring(0, 300)}...`);

    // Build promptmap command
    const pythonCmd = process.env.PYTHON_CMD || 'python3';
    const args = [
      promptmapPath,
      '--target-model', 'external',
      '--target-model-type', 'http',
      '--http-config', configPath,
      '--controller-model', controllerModel!,
      '--controller-model-type', controllerModelType!,
      '--iterations', iterations!.toString(),
      '--output', outputPath,
    ];

    if (firewall && passCondition) {
      args.push('--firewall');
      args.push('--pass-condition', passCondition);
    }

    if (rules && rules.length > 0) {
      args.push('--rules', rules.join(','));
    }

    if (ruleTypes && ruleTypes.length > 0) {
      args.push('--rule-type', ruleTypes.join(','));
    } else if (!rules || rules.length === 0) {
      // If no specific rules or rule types specified, explicitly specify common rule types
      // This ensures promptmap finds and runs rules (promptmap sometimes has issues with default "all")
      args.push('--rule-type', 'prompt_stealing,jailbreak,distraction,harmful');
    }

    // Execute promptmap from the promptmap directory to ensure rules are found
    const promptmapDir = path.dirname(promptmapPath);
    console.log(`[Prompt Injection] Executing promptmap from directory: ${promptmapDir}`);
    console.log(`[Prompt Injection] Executing promptmap with args:`, args);
    let stdout = '';
    let stderr = '';
    const promptmap = spawn(pythonCmd, args, { 
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
      cwd: promptmapDir  // Set working directory to promptmap directory
    });

    const timeoutMs = 1000 * 300; // 5 minutes timeout
    const timer = setTimeout(() => {
      try {
        promptmap.kill('SIGTERM');
        stderr += '\nTimeout: promptmap execution exceeded 5 minutes';
      } catch {}
    }, timeoutMs);

    promptmap.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    promptmap.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    const exitCode = await new Promise<number>((resolve) => {
      promptmap.on('error', (err) => {
        console.error('promptmap spawn error:', err);
        clearTimeout(timer);
        resolve(-1);
      });
      promptmap.on('close', (code) => {
        clearTimeout(timer);
        resolve(code ?? -1);
      });
    });

    // Read results if output file exists
    let results: any = {};
    if (existsSync(outputPath)) {
      try {
        const outputContent = readFileSync(outputPath, 'utf8').trim();
        if (!outputContent) {
          console.error('promptmap output file is empty', { exitCode, stderr: stderr.substring(0, 500), stdout: stdout.substring(0, 500) });
          return res.status(500).json({ 
            error: 'promptmap produced empty output', 
            message: `Output file exists but is empty. Exit code: ${exitCode}, stderr: ${stderr.substring(0, 2000)}, stdout: ${stdout.substring(0, 2000)}` 
          });
        }
        results = JSON.parse(outputContent);
        if (!results || Object.keys(results).length === 0) {
          console.error('promptmap results are empty', { exitCode, stderr: stderr.substring(0, 500), stdout: stdout.substring(0, 500) });
          return res.status(500).json({ 
            error: 'promptmap produced no test results', 
            message: `Output file parsed but contains no test results. Exit code: ${exitCode}, stderr: ${stderr.substring(0, 2000)}, stdout: ${stdout.substring(0, 2000)}` 
          });
        }
        console.log(`promptmap completed successfully with ${Object.keys(results).length} test results`);
      } catch (parseErr: any) {
        console.error('Failed to parse promptmap output:', parseErr);
        const fileContent = existsSync(outputPath) ? readFileSync(outputPath, 'utf8').substring(0, 500) : 'file not found';
        return res.status(500).json({ 
          error: 'Failed to parse promptmap results', 
          message: `Output file exists but could not be parsed. Parse error: ${parseErr?.message || String(parseErr)}, File content: ${fileContent}, stdout: ${stdout.substring(0, 500)}, stderr: ${stderr.substring(0, 1000)}` 
        });
      }
    } else {
      // If no output file, check if there was an error
      console.error('promptmap output file not found', { exitCode, stderr: stderr.substring(0, 500), stdout: stdout.substring(0, 500), configPath, outputPath });
      
      // Check for YAML parsing errors in stderr or stdout
      const errorOutput = stderr + stdout;
      if (errorOutput.includes('while scanning') || errorOutput.includes('could not find expected') || 
          errorOutput.includes('YAML') || errorOutput.includes('yaml')) {
        // Extract the YAML error message
        const yamlErrorMatch = errorOutput.match(/Error:.*?(?=Usage Examples:|$)/s);
        const yamlError = yamlErrorMatch ? yamlErrorMatch[0].replace(/Error:\s*/, '').trim() : 
                         errorOutput.match(/could not find expected.*/)?.[0] || 
                         'YAML parsing error detected';
        
        return res.status(400).json({ 
          error: 'Invalid YAML configuration', 
          message: `YAML parsing error: ${yamlError}. Please ensure your YAML is properly formatted. Remove any cookie/session strings and ensure all keys have colons (:) after them.` 
        });
      }
      
      return res.status(500).json({ 
        error: 'promptmap execution failed', 
        message: `Output file not created. Exit code: ${exitCode}, stderr: ${stderr.substring(0, 2000)}, stdout: ${stdout.substring(0, 2000)}` 
      });
    }

    // Transform results to recon-app format
    const transformedResults = Object.entries(results).map(([ruleName, ruleData]: [string, any]) => {
      const data = ruleData as any;
      // Handle both failed_result and uncertain_result
      const resultData = data.failed_result || data.uncertain_result || {};
      const status = data.status || (data.passed === false ? 'fail' : data.passed === true ? 'pass' : 'uncertain');
      
      return {
        ruleName,
        type: data.type || 'unknown',
        severity: data.severity || 'medium',
        passed: data.passed === true, // Only true if explicitly passed
        passRate: data.pass_rate || '0/0',
        response: resultData.response || data.response || '',
        evaluation: resultData.evaluation || data.evaluation || status,
        reason: resultData.reason || data.reason || '',
        failedResult: data.failed_result || data.uncertain_result || null,
        status: status,
      };
    });

    // Cleanup temp files
    try {
      if (existsSync(configPath)) unlinkSync(configPath);
      if (existsSync(outputPath)) unlinkSync(outputPath);
    } catch (cleanupErr) {
      console.warn('Failed to cleanup temp files:', cleanupErr);
    }

    res.json({
      target,
      count: transformedResults.length,
      results: transformedResults,
    });
  } catch (err: any) {
    console.error('Prompt injection test error:', err);
    
    // Cleanup on error
    try {
      if (existsSync(configPath)) unlinkSync(configPath);
      if (existsSync(outputPath)) unlinkSync(outputPath);
    } catch {}

    res.status(500).json({ 
      error: 'Prompt injection test failed', 
      message: err.shortMessage || err.message || String(err) 
    });
  }
});

// POST /api/garak-scan
// Supports:
// - Normal garak model scans via { targetType, targetName }
// - HTTP endpoint scans via { httpTarget: { uri, headers, reqTemplateJsonObject, responseJsonField, ... } }
app.post('/api/garak-scan', reconLimiter, async (req, res) => {
  const parse = GarakScanQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }

  const {
    targetLabel,
    probes,
    extraArgs,
    generations,
    generatorOptions,
    httpTarget,
  } = parse.data;

  // Back-compat: previous UI posted `{ model: "..." }`
  const legacyModel = (parse.data as any).model as string | undefined;

  // Decide target type/name
  let targetType = parse.data.targetType?.trim() || legacyModel?.trim() || '';
  let targetName = parse.data.targetName?.trim() || '';
  let resolvedGeneratorOptions: Record<string, any> | undefined = generatorOptions ? { ...generatorOptions } : undefined;

  if (httpTarget) {
    // garak expects generator option files to be namespaced, e.g.:
    // { "rest": { "RestGenerator": { ... } } }
    targetType = 'rest';
    targetName = httpTarget.uri;

    // Normalize headers: ensure Cookie header is properly formatted
    const normalizedHeaders: Record<string, string> = { ...(httpTarget.headers || {}) };
    
    // Fix common Cookie header issues:
    // Users often paste cookie values from Burp/DevTools without the "cf_clearance=" prefix
    if (normalizedHeaders.Cookie) {
      const cookieValue = normalizedHeaders.Cookie.trim();
      const originalCookie = cookieValue;
      
      // Check if Cookie header is missing the "cf_clearance=" prefix
      if (cookieValue && !cookieValue.includes('cf_clearance=')) {
        // Split by semicolon to handle multiple cookies
        const parts = cookieValue.split(';').map(p => p.trim()).filter(Boolean);
        const fixedParts: string[] = [];
        
        for (const part of parts) {
          if (part.includes('=')) {
            // Already has name=value format (e.g., "session=...")
            fixedParts.push(part);
          } else {
            // Value without name - determine which cookie it is
            if (part.length > 100 && part.includes('-') && part.match(/\d{10}/)) {
              // Long value with timestamp pattern - likely cf_clearance
              fixedParts.push(`cf_clearance=${part}`);
            } else if (part.startsWith('eyJ') || part.match(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)) {
              // JWT-like token - likely session cookie
              fixedParts.push(`session=${part}`);
            } else {
              // Unknown format - assume cf_clearance if it's the first part, session if it's after a semicolon
              if (fixedParts.length === 0) {
                fixedParts.push(`cf_clearance=${part}`);
              } else {
                fixedParts.push(`session=${part}`);
              }
            }
          }
        }
        
        if (fixedParts.length > 0) {
          normalizedHeaders.Cookie = fixedParts.join('; ');
          console.log(`[Garak] Fixed Cookie header format. Original: ${originalCookie.substring(0, 100)}... Fixed: ${normalizedHeaders.Cookie.substring(0, 100)}...`);
        }
      }
    }

    // Log headers for debugging (redact sensitive cookie values)
    const headersForLog = { ...normalizedHeaders };
    if (headersForLog.Cookie) {
      const cookieParts = headersForLog.Cookie.split(';');
      headersForLog.Cookie = cookieParts.map((p: string) => {
        if (p.includes('cf_clearance=')) {
          const parts = p.split('=');
          const val = parts[1];
          if (val) {
            return `cf_clearance=${val.substring(0, 20)}...${val.length} chars`;
          }
        }
        if (p.includes('session=')) {
          const parts = p.split('=');
          const val = parts[1];
          if (val) {
            return `session=${val.substring(0, 20)}...${val.length} chars`;
          }
        }
        return p;
      }).join('; ');
    }
    console.log(`[Garak] REST scan config:`, {
      uri: httpTarget.uri,
      method: (httpTarget.method || 'post').toLowerCase(),
      headers: headersForLog,
      hasCookie: !!normalizedHeaders.Cookie,
      cookieLength: normalizedHeaders.Cookie?.length || 0,
    });

    const opts: Record<string, any> = {
      uri: httpTarget.uri,
      method: (httpTarget.method || 'post').toLowerCase(),
      headers: normalizedHeaders,
      request_timeout: httpTarget.requestTimeout ?? 20,
      verify_ssl: httpTarget.verifySsl ?? true,
    };

    if (httpTarget.reqTemplate && httpTarget.reqTemplate.trim()) {
      opts.req_template = httpTarget.reqTemplate;
    } else if (httpTarget.reqTemplateFormData && Object.keys(httpTarget.reqTemplateFormData).length) {
      // Multipart/form-data: garak's REST generator supports req_template_form_data
      opts.req_template_form_data = httpTarget.reqTemplateFormData;
      // Remove Content-Type header if present - requests library will set it with boundary
      if (normalizedHeaders['Content-Type']?.includes('multipart/form-data')) {
        delete normalizedHeaders['Content-Type'];
        delete opts.headers['Content-Type'];
      }
    } else if (httpTarget.reqTemplateJsonObject && Object.keys(httpTarget.reqTemplateJsonObject).length) {
      opts.req_template_json_object = httpTarget.reqTemplateJsonObject;
    } else {
      // Sensible default for JSON chat endpoints
      opts.req_template_json_object = { message: '$INPUT' };
    }

    // Response parsing
    opts.response_json = true;
    opts.response_json_field = httpTarget.responseJsonField || '$.bot_response.response';

    resolvedGeneratorOptions = { rest: { RestGenerator: opts } };
  }

  if (!targetType) {
    return res.status(400).json({ error: 'targetType is required (or provide httpTarget.uri for REST scans)' });
  }

  // Set up garak runtime dirs inside the workspace so it doesn't try to write to /root/.config
  const garakStateDir = path.resolve(process.cwd(), '.garak_state');
  const garakHome = path.join(garakStateDir, 'home');
  const garakCache = path.join(garakStateDir, 'cache');
  const garakRuns = path.join(garakStateDir, 'runs');
  safeMkdir(garakHome);
  safeMkdir(garakCache);
  safeMkdir(garakRuns);

  // Locate local garak install (optional). If absent, rely on system/site garak.
  const garakPyCandidates = [
    process.env.GARAK_PYTHONPATH,
    path.resolve(__dirname, '../tools/garak_py'),
    path.resolve(__dirname, '../../tools/garak_py'),
    path.resolve(process.cwd(), 'tools/garak_py'),
    path.resolve(process.cwd(), 'backend/tools/garak_py'),
  ].filter(Boolean) as string[];
  const garakPyPath = garakPyCandidates.find(p => p && existsSync(p)) || null;

  const runId = randomUUID();
  const reportPrefix = path.join(garakRuns, `garak-${runId}`);
  const reportJsonl = `${reportPrefix}.report.jsonl`;
  const reportHtml = `${reportPrefix}.report.html`;

  // Write generator option file (if provided)
  let genOptPath: string | null = null;
  if (resolvedGeneratorOptions && Object.keys(resolvedGeneratorOptions).length) {
    genOptPath = `${reportPrefix}.generator_options.json`;
    try {
      writeFileSync(genOptPath, JSON.stringify(resolvedGeneratorOptions, null, 2), 'utf8');
    } catch (e: any) {
      console.error('Failed to write garak generator options file:', e?.message || e);
      genOptPath = null;
    }
  }

  try {
    const pythonCmd = process.env.PYTHON_CMD || 'python3';
    const args: string[] = ['-m', 'garak', '--target_type', targetType];

    if (targetName) args.push('--target_name', targetName);
    if (typeof generations === 'number') args.push('--generations', String(generations));

    // Probes
    if (probes && probes.length > 0) {
      args.push('--probes', probes.join(','));
    }

    // Report prefix so we can parse JSONL and return structured output
    args.push('--report_prefix', reportPrefix);

    // Generator options file
    if (genOptPath) {
      args.push('--generator_option_file', genOptPath);
    }

    // Extra CLI args (advanced; passed as-is)
    if (extraArgs && extraArgs.trim()) {
      const extraSplit = extraArgs.trim().split(/\s+/).filter(Boolean);
      args.push(...extraSplit);
    }

    let stdout = '';
    let stderr = '';

    const env = { ...process.env } as Record<string, string>;
    env.HOME = garakHome;
    env.XDG_CONFIG_HOME = garakHome;
    env.XDG_CACHE_HOME = garakCache;
    if (garakPyPath) {
      env.PYTHONPATH = env.PYTHONPATH
        ? `${garakPyPath}${path.delimiter}${env.PYTHONPATH}`
        : garakPyPath;
    }

    const child = spawn(pythonCmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });

    const maxRuntimeMs = 1000 * 60 * 8; // 8 minutes hard cap
    const timer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch {}
    }, maxRuntimeMs);

    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });

    const exitCode: number = await new Promise((resolve) => {
      child.on('error', (err) => {
        console.error('garak spawn error:', err);
        clearTimeout(timer);
        resolve(-1);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve(code ?? -1);
      });
    });

    // Parse digest for a structured summary
    const digest = existsSync(reportJsonl) ? parseJsonlDigest(reportJsonl) : null;

    // Detect common issues and provide helpful error messages
    let errorHint: string | null = null;
    
    // Check if scan made progress (indicates it was working before the error)
    const madeProgress = stdout.includes('%|') || stdout.match(/\d+\/\d+/);
    
    if (stderr.includes('NameResolutionError') || stderr.includes('Failed to resolve') || stderr.includes('Temporary failure in name resolution')) {
      if (madeProgress) {
        errorHint = 'DNS resolution failed during scan (temporary network issue). The scan was working successfully (made progress) but hit a DNS error. This is usually temporary - try running the scan again. The partial results may still be available in the report file.';
      } else {
        errorHint = 'DNS resolution failed: Cannot resolve the target domain. Check your network connection, DNS settings, or verify the domain name is correct.';
      }
    } else if (stderr.includes('403') || stderr.includes('FORBIDDEN')) {
      // Check if this is likely Cloudflare protection
      const hasCfClearance = httpTarget?.headers?.Cookie?.includes('cf_clearance') || 
                             httpTarget?.headers?.cookie?.includes('cf_clearance');
      const isCloudflareDomain = httpTarget?.uri && (
        httpTarget.uri.includes('hacktheagent.com') ||
        httpTarget.uri.includes('cloudflare') ||
        stderr.includes('cf-ray') ||
        stderr.includes('cloudflare')
      );
      
      if (hasCfClearance || isCloudflareDomain) {
        errorHint = '⚠️ Cloudflare Advanced Bot Protection detected: Even with correct cookies, Cloudflare blocks non-browser HTTP clients (like Python requests) because it checks TLS fingerprinting, HTTP/2 characteristics, and browser environment signals that cannot be replicated. This is a fundamental limitation, not a bug. SOLUTION: Use the "Prompt Injection Test" feature in the sidebar - it uses promptmap with Playwright (real browser) which can bypass Cloudflare protection.';
      } else {
        errorHint = '403 Forbidden: The target is rejecting the request. Possible causes: missing/invalid authentication headers, bot protection (Cloudflare/WAF), IP-based blocking, or incorrect request format. If you see "cf_clearance" in your cookies, this is Cloudflare protection - use "Prompt Injection Test" instead.';
      }
    } else if (stderr.includes('401') || stderr.includes('UNAUTHORIZED')) {
      errorHint = '401 Unauthorized: Authentication failed. Verify your API keys, cookies, or authentication headers are correct and not expired.';
    } else if (stderr.includes('ConnectionError') || stderr.includes('Failed to establish')) {
      if (madeProgress) {
        errorHint = 'Connection error during scan (network issue). The scan was working but lost connection. This may be temporary - try running the scan again. Partial results may be available.';
      } else {
        errorHint = 'Connection failed: The target endpoint is unreachable. Check the URL is correct and the service is online.';
      }
    } else if (madeProgress && exitCode !== 0) {
      errorHint = 'Scan encountered an error but made progress. Partial results may be available in the report. Check stderr for details.';
    }

    return res.json({
      target: targetLabel || targetName || targetType,
      targetType,
      targetName: targetName || null,
      probes: probes || [],
      generations: generations ?? null,
      ok: exitCode === 0,
      exitCode,
      report: {
        jsonl: existsSync(reportJsonl) ? reportJsonl : null,
        html: existsSync(reportHtml) ? reportHtml : null,
      },
      digest,
      stdout,
      stderr,
      errorHint,
    });
  } catch (err: any) {
    console.error('Garak scan error:', err);
    return res.status(500).json({
      error: 'Garak scan failed',
      message: err?.message || String(err),
    });
  } finally {
    // Best-effort cleanup of generator options file (keep report files)
    try { if (genOptPath && existsSync(genOptPath)) unlinkSync(genOptPath); } catch {}
  }
});

// ── Subdomain Takeover fingerprints ──────────────────────────────────────
// Each entry: CNAME pattern to match + body fingerprint that confirms takeover is possible
const TAKEOVER_FINGERPRINTS: Array<{ service: string; cname: RegExp; body?: RegExp; statusCodes?: number[] }> = [
  { service: 'GitHub Pages',      cname: /github\.io$/i,                   body: /There isn't a GitHub Pages site here|404 There is no GitHub Pages site/i },
  { service: 'Heroku',            cname: /herokuapp\.com$|herokudns\.com$/i, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { service: 'Fastly',            cname: /fastly\.net$/i,                   body: /Fastly error: unknown domain/i },
  { service: 'Shopify',           cname: /myshopify\.com$/i,                body: /Sorry, this shop is currently unavailable/i },
  { service: 'Tumblr',            cname: /tumblr\.com$/i,                   body: /Whatever you were looking for doesn't currently exist at this address/i },
  { service: 'Squarespace',       cname: /squarespace\.com$/i,              body: /No Such Account|squarespace\.com/i },
  { service: 'Ghost',             cname: /ghost\.io$/i,                     body: /The thing you were looking for is no longer here/i },
  { service: 'Cargo',             cname: /cargocollective\.com$/i,          body: /404 Not Found/i },
  { service: 'Zendesk',           cname: /zendesk\.com$/i,                  body: /Help Center Closed/i },
  { service: 'Desk.com',          cname: /desk\.com$/i,                     body: /Sorry, We Couldn't Find That Page/i },
  { service: 'Unbounce',          cname: /unbouncepages\.com$/i,            body: /The requested URL was not found on this server/i },
  { service: 'Strikingly',        cname: /strikingly\.com$/i,               body: /page not found/i },
  { service: 'Surge.sh',          cname: /surge\.sh$/i,                     body: /project not found/i },
  { service: 'Netlify',           cname: /netlify\.app$|netlify\.com$/i,    body: /Not Found - Request ID/i },
  { service: 'Vercel',            cname: /vercel\.app$/i,                   body: /The deployment could not be found/i },
  { service: 'AWS S3',            cname: /s3\.amazonaws\.com|s3-website/i,  body: /NoSuchBucket|The specified bucket does not exist/i },
  { service: 'Azure',             cname: /azurewebsites\.net|cloudapp\.net|trafficmanager\.net/i, body: /404 Web Site not found/i },
  { service: 'Bitbucket',         cname: /bitbucket\.io$/i,                 body: /Repository not found/i },
  { service: 'HubSpot',           cname: /hubspot\.net|hs-sites\.com$/i,    body: /Domain not configured/i },
  { service: 'Webflow',           cname: /webflow\.io$/i,                   body: /The page you are looking for doesn't exist/i },
  { service: 'Pantheon',          cname: /pantheonsite\.io$/i,              body: /The gods are wise, but do not know of the site/i },
  { service: 'Readme.io',         cname: /readme\.io$/i,                    body: /Project doesnt exist/i },
  { service: 'Acquia',            cname: /acquia-sites\.com$/i,             body: /The site you are looking for could not be found/i },
  { service: 'Kinsta',            cname: /kinsta\.cloud$/i,                 body: /No Site For Domain/i },
  { service: 'WP Engine',         cname: /wpengine\.com$/i,                 body: /The site you were looking for couldn't be found/i },
];

const resolveCname = promisify(dns.resolveCname);

async function checkSubdomainTakeover(subdomain: string): Promise<{
  subdomain: string;
  vulnerable: boolean;
  service: string | null;
  cname: string | null;
  evidence: string;
  severity: 'high' | 'info';
}> {
  let cname: string | null = null;
  try {
    const cnames = await (resolveCname as any)(subdomain);
    cname = Array.isArray(cnames) && cnames.length > 0 ? String(cnames[0]) : null;
  } catch {
    // No CNAME — not vulnerable via this vector
    return { subdomain, vulnerable: false, service: null, cname: null, evidence: 'No CNAME record', severity: 'info' };
  }

  if (!cname) return { subdomain, vulnerable: false, service: null, cname: null, evidence: 'No CNAME record', severity: 'info' };

  // Find matching fingerprint
  const fp = TAKEOVER_FINGERPRINTS.find(f => f.cname.test(cname!));
  if (!fp) {
    return { subdomain, vulnerable: false, service: null, cname, evidence: `CNAME → ${cname} (no known vulnerable service)`, severity: 'info' };
  }

  // Probe the subdomain for the body fingerprint
  if (fp.body) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      try {
        const resp = await fetch(`https://${subdomain}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ReconApp/1.0)' },
          signal: controller.signal,
          redirect: 'follow',
        });
        const body = await resp.text();
        clearTimeout(timer);
        if (fp.body.test(body)) {
          return { subdomain, vulnerable: true, service: fp.service, cname, evidence: `CNAME → ${cname} | Body matches "${fp.body.source.substring(0, 60)}"`, severity: 'high' };
        }
        return { subdomain, vulnerable: false, service: fp.service, cname, evidence: `CNAME → ${cname} (${fp.service} CNAME but body fingerprint not matched)`, severity: 'info' };
      } finally {
        clearTimeout(timer);
      }
    } catch {
      // If we can't reach it at all, that's also suspicious — CNAME points somewhere unreachable
      return { subdomain, vulnerable: true, service: fp.service, cname, evidence: `CNAME → ${cname} | Unreachable (${fp.service} — likely unclaimed)`, severity: 'high' };
    }
  }

  return { subdomain, vulnerable: true, service: fp.service, cname, evidence: `CNAME → ${cname} (${fp.service})`, severity: 'high' };
}

// POST /api/takeover — Subdomain Takeover Detection (streaming NDJSON)
app.post('/api/takeover', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  const { target } = parse.data;

  // Accept pre-discovered subdomains from frontend (avoids re-running subfinder)
  const rawSubs: unknown = req.body.subdomains;
  let subdomains: string[] = Array.isArray(rawSubs)
    ? (rawSubs as string[]).filter((s): s is string => typeof s === 'string' && isValidDomain(s))
    : [];

  if (subdomains.length === 0) {
    // Fallback: run subfinder
    try {
      const subfinder = spawn('subfinder', ['-silent', '-d', target], { stdio: ['ignore', 'pipe', 'pipe'] });
      let sfOut = '';
      const timer = setTimeout(() => { try { subfinder.kill('SIGTERM'); } catch {} }, 60000);
      subfinder.stdout.on('data', (c: Buffer) => { sfOut += c.toString(); });
      await new Promise<void>(resolve => { subfinder.on('close', () => { clearTimeout(timer); resolve(); }); subfinder.on('error', resolve as any); });
      subdomains = Array.from(new Set(sfOut.split('\n').map(l => l.trim()).filter(Boolean).filter(isValidDomain)));
    } catch {}
    if (subdomains.length === 0) subdomains = [target];
  }

  console.log(`[takeover] checking ${subdomains.length} subdomains for ${target}`);

  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write(JSON.stringify({ type: 'start', target, total: subdomains.length }) + '\n');

  const CONCURRENCY = 20;
  let vulnerable = 0;
  for (let i = 0; i < subdomains.length; i += CONCURRENCY) {
    const batch = subdomains.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(async (sub) => {
      const result = await checkSubdomainTakeover(sub);
      if (result.vulnerable) vulnerable++;
      try { res.write(JSON.stringify({ type: 'result', ...result }) + '\n'); } catch {}
    }));
  }

  try {
    res.write(JSON.stringify({ type: 'done', target, total: subdomains.length, vulnerable }) + '\n');
    res.end();
  } catch {}
});

// POST /api/nuclei — Nuclei vulnerability scan (streaming NDJSON)
app.post('/api/nuclei', reconLimiter, async (req, res) => {
  const parse = ReconQuery.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  const { target } = parse.data;

  // Accept pre-discovered live subdomains from frontend
  const rawSubs: unknown = req.body.subdomains;
  let subdomains: string[] = Array.isArray(rawSubs)
    ? (rawSubs as string[]).filter((s): s is string => typeof s === 'string' && isValidDomain(s))
    : [];

  const templateArg: string = typeof req.body.templates === 'string' && req.body.templates.trim()
    ? req.body.templates.trim()
    : 'http/exposures,http/misconfiguration,http/takeovers,http/vulnerabilities,http/default-logins,http/exposed-panels,network/exposures,network/misconfiguration';

  const severityArg: string = typeof req.body.severity === 'string' && req.body.severity.trim()
    ? req.body.severity.trim()
    : 'critical,high,medium';

  if (subdomains.length === 0) subdomains = [target];

  // Build target list: https + http for each subdomain
  const targets = subdomains.flatMap(s => [`https://${s}`, `http://${s}`]);

  console.log(`[nuclei] scanning ${subdomains.length} subdomains (${targets.length} URLs) for ${target}`);

  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write(JSON.stringify({ type: 'start', target, total: targets.length }) + '\n');

  // Write targets to a temp file so we don't hit arg length limits
  const tmpTargets = path.join(process.cwd(), `.nuclei-targets-${Date.now()}.txt`);
  try {
    writeFileSync(tmpTargets, targets.join('\n'), 'utf8');
  } catch (e) {
    res.write(JSON.stringify({ type: 'error', message: 'Failed to write targets file' }) + '\n');
    res.end();
    return;
  }

  const args = [
    '-l', tmpTargets,
    '-t', templateArg,
    '-severity', severityArg,
    '-json-export', '-',   // stream JSON findings to stdout
    '-silent',
    '-no-color',
    '-rate-limit', '50',
    '-bulk-size', '25',
    '-concurrency', '25',
    '-timeout', '10',
    '-retries', '1',
    '-stats',
  ];

  const nuclei = spawn('nuclei', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const nucleiTimer = setTimeout(() => { try { nuclei.kill('SIGTERM'); } catch {} }, 1000 * 60 * 15); // 15 min cap

  let buf = '';
  let findingCount = 0;

  nuclei.stdout.on('data', (chunk: Buffer) => {
    buf += chunk.toString();
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const finding = JSON.parse(trimmed);
        findingCount++;
        // Shape the finding for the frontend
        const shaped = {
          type: 'finding',
          templateId: finding['template-id'] ?? finding.templateID ?? '',
          name: finding.info?.name ?? finding['template-id'] ?? 'Unknown',
          severity: (finding.info?.severity ?? 'info').toLowerCase(),
          host: finding.host ?? finding.matched ?? '',
          url: finding['matched-at'] ?? finding.matched ?? finding.host ?? '',
          description: finding.info?.description ?? '',
          tags: finding.info?.tags ?? [],
          reference: Array.isArray(finding.info?.reference) ? finding.info.reference : [],
          extractedResults: finding['extracted-results'] ?? [],
          curl: finding['curl-command'] ?? null,
          timestamp: finding.timestamp ?? new Date().toISOString(),
        };
        try { res.write(JSON.stringify(shaped) + '\n'); } catch {}
      } catch {
        // Not JSON — nuclei progress/stats line, skip
      }
    }
  });

  nuclei.stderr.on('data', (chunk: Buffer) => {
    // nuclei writes stats/progress to stderr — forward as info frames
    const text = chunk.toString().trim();
    if (text) {
      try { res.write(JSON.stringify({ type: 'progress', message: text }) + '\n'); } catch {}
    }
  });

  await new Promise<void>(resolve => {
    nuclei.on('close', () => { clearTimeout(nucleiTimer); resolve(); });
    nuclei.on('error', () => { clearTimeout(nucleiTimer); resolve(); });
  });

  // Cleanup temp file
  try { unlinkSync(tmpTargets); } catch {}

  try {
    res.write(JSON.stringify({ type: 'done', target, findings: findingCount }) + '\n');
    res.end();
  } catch {}
});

// ── Google Dorking ────────────────────────────────────────────────────────
// Reads dorks.txt, substitutes the target domain, and returns dork queries
// with Google search URLs. If SERPAPI_KEY is set, also fetches live results.

const DorkingQuery = z.object({
  target: z.string().trim().toLowerCase().regex(hostnameRegex, 'Invalid domain'),
});

function loadDorksFile(): { category: string; query: string }[] {
  // Look for dorks.txt relative to the project root (one level up from backend/)
  const candidates = [
    path.join(process.cwd(), '..', 'dorks.txt'),
    path.join(process.cwd(), 'dorks.txt'),
    path.join(__dirname, '..', '..', 'dorks.txt'),
  ];
  let raw = '';
  for (const p of candidates) {
    if (existsSync(p)) { raw = readFileSync(p, 'utf8'); break; }
  }
  if (!raw) return [];

  const dorks: { category: string; query: string }[] = [];
  let currentCategory = 'General';
  const separator = /^-{10,}$/;
  let inAdvancedSection = false;

  // Accumulate multi-line dork blocks (lines starting with '(' that span multiple lines)
  let pendingBlock = '';

  const flushBlock = () => {
    if (!pendingBlock.trim()) return;
    const combined = pendingBlock.replace(/\s+/g, ' ').trim();
    if (combined) dorks.push({ category: currentCategory, query: combined });
    pendingBlock = '';
  };

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();

    // Separator line — switch to advanced/combined section
    if (separator.test(trimmed)) {
      flushBlock();
      if (!inAdvancedSection) {
        inAdvancedSection = true;
        currentCategory = 'Bug Bounty / VDP';
      } else {
        // Second separator — end of file content
        inAdvancedSection = false;
      }
      continue;
    }

    if (!trimmed) {
      // Empty line flushes any pending multi-line block
      flushBlock();
      continue;
    }

    // Skip comment lines and section header annotations
    if (trimmed.startsWith('//') || trimmed.startsWith('#')) continue;
    // Skip lines that are purely navigation labels (e.g. "for domain dorking ->")
    if (/^for\s+\w+\s+dorking/i.test(trimmed)) continue;

    // In the advanced section, lines starting with '(' are multi-line combined dorks
    if (inAdvancedSection) {
      const isDorkLine = /^\(/.test(trimmed) ||
        /^site:|^inurl:|^intext:|^intitle:|^ext:|^filetype:|^cache:|^related:|^link:|^info:/.test(trimmed) ||
        /^"/.test(trimmed);

      if (isDorkLine) {
        // If we already have a pending block that starts a new top-level query, flush it
        // A new top-level query starts with '(' or a standalone operator
        if (pendingBlock && /^\(/.test(trimmed)) {
          flushBlock();
        }
        pendingBlock += (pendingBlock ? ' ' : '') + trimmed;
      } else {
        // Non-dork line in advanced section — could be a category label
        flushBlock();
        if (trimmed.length > 3 && !/^-+$/.test(trimmed)) {
          currentCategory = trimmed;
        }
      }
      continue;
    }

    // Standard section (before first separator)
    const isDork = /site:|inurl:|intext:|intitle:|ext:|filetype:|insite:/.test(trimmed) ||
      /^"/.test(trimmed) ||
      /^site\*|^inurl|^intext|^intitle|^filetype/.test(trimmed) ||
      /^\(site:/.test(trimmed);

    if (isDork) {
      dorks.push({ category: currentCategory, query: trimmed });
    } else if (trimmed.length > 3 && !/^-+$/.test(trimmed) && !trimmed.startsWith('site:*<')) {
      // Treat as a category label
      currentCategory = trimmed;
    }
  }

  // Flush any remaining block
  flushBlock();

  return dorks;
}

function substituteDomain(query: string, target: string): string {
  // Handle target.com placeholder (new format)
  let result = query
    .replace(/\btarget\[?\.\]?com\b/gi, target)
    .replace(/\btarget\.com\b/gi, target);
  // Also handle old example.com placeholder (legacy format)
  result = result
    .replace(/example\[?\.\]?com/gi, target)
    .replace(/example\.com/gi, target);
  // Handle "target" standalone in quoted strings like "target.com" OR "target"
  result = result.replace(/"target"/g, `"${target.split('.')[0]}"`);
  return result;
}

// ── GitHub Dorking ────────────────────────────────────────────────────────
// Reads github_dorks.txt, substitutes the target domain, and searches GitHub
// code search API using the configured GITHUB_PAT.

const GithubDorkingQuery = z.object({
  target: z.string().trim().toLowerCase().regex(hostnameRegex, 'Invalid domain'),
});

function loadGithubDorksFile(): { category: string; query: string }[] {
  const candidates = [
    path.join(process.cwd(), '..', 'github_dorks.txt'),
    path.join(process.cwd(), 'github_dorks.txt'),
    path.join(__dirname, '..', '..', 'github_dorks.txt'),
  ];
  let raw = '';
  for (const p of candidates) {
    if (existsSync(p)) { raw = readFileSync(p, 'utf8'); break; }
  }
  if (!raw) return [];

  const dorks: { category: string; query: string }[] = [];
  let currentCategory = 'Credentials & Secrets';
  let pendingBlock = '';

  const flushBlock = () => {
    const combined = pendingBlock.replace(/\s+/g, ' ').trim();
    if (combined) {
      // Skip lines that are just GitHub web search URLs (not API-compatible)
      if (!combined.startsWith('gist.github.com') && !combined.startsWith('github.com/search')) {
        dorks.push({ category: currentCategory, query: combined });
      }
    }
    pendingBlock = '';
  };

  // Category mapping based on content keywords
  function inferCategory(query: string): string {
    if (/private.key|BEGIN RSA|BEGIN OPENSSH|BEGIN PRIVATE|\.pem|\.ovpn|id_rsa/i.test(query)) return 'Private Keys & Certs';
    if (/DB_PASSWORD|DATABASE_URL|JDBC|connectionString|QSqlDatabase|setPassword|mongo:|postgres:|mysql:|redis:/i.test(query)) return 'Database Credentials';
    if (/apiKey|api_key|api_token|client_secret|consumer_key|databaseURL|storageBucket|firebase|authDomain/i.test(query)) return 'API Keys & Tokens';
    if (/ldap|LDAP|Active Directory|adfs|saml|okta|onelogin/i.test(query)) return 'Auth & SSO';
    if (/jenkins|Jenkinsfile|gitlab-ci|circleci|drone|travis|argo|tekton/i.test(query)) return 'CI/CD';
    if (/send_keys|selenium|webdriver/i.test(query)) return 'Automation';
    if (/slack_token|xoxb|xoxp|github_token|ghp_|glpat-|sk-|stripe_secret|twilio|sendgrid/i.test(query)) return 'Service Tokens';
    if (/s3\.amazonaws|blob\.core\.windows|storage\.googleapis|firebaseio|cloudfront/i.test(query)) return 'Cloud Storage';
    if (/docker-compose|kubernetes|kubeconfig|\.kube|helm|terraform/i.test(query)) return 'Infrastructure';
    if (/openid|oauth|oauth_token|refresh_token|jwt|bearer/i.test(query)) return 'OAuth & JWT';
    if (/mailgun|sendgrid|smtp|ses|postmark/i.test(query)) return 'Email Services';
    if (/stripe|paypal|braintree|square/i.test(query)) return 'Payment APIs';
    if (/twilio|nexmo|plivo/i.test(query)) return 'Telephony';
    if (/openai|gpt|anthropic|claude/i.test(query)) return 'AI Services';
    if (/\.npmrc|\.pypirc|\.dockercfg|\.git-credentials|\.netrc/i.test(query)) return 'Config Files';
    if (/language:|path:src\//i.test(query)) return 'Source Code';
    return 'Credentials & Secrets';
  }

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) {
      flushBlock();
      continue;
    }
    if (trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

    // Lines starting with '(' are dork query lines (possibly multi-line blocks)
    const isDorkLine = /^\(/.test(trimmed) ||
      /^NOT\s/.test(trimmed) ||
      /^(path:|language:|extension:|filename:)/.test(trimmed);

    if (isDorkLine) {
      pendingBlock += (pendingBlock ? ' ' : '') + trimmed;
    } else {
      // Non-dork line — flush pending and skip (it's a URL or label)
      flushBlock();
    }
  }
  flushBlock();

  // Infer categories from query content
  return dorks.map(d => ({ ...d, category: inferCategory(d.query) }));
}

function substituteGithubDomain(query: string, target: string): string {
  const domain = target; // e.g. "example.com"
  const orgName = target.split('.')[0] ?? target; // e.g. "example"
  return query
    .replace(/"target\.com"/g, `"${domain}"`)
    .replace(/"target"/g, `"${orgName}"`)
    .replace(/"@target\.com"/g, `"@${domain}"`)
    .replace(/"@target"/g, `"@${domain}"`)
    .replace(/"\*\.target\.com"/g, `"*.${domain}"`)
    .replace(/\btarget\.com\b/g, domain)
    .replace(/\btarget\b/g, orgName);
}

interface GithubSearchItem {
  name: string;
  path: string;
  html_url: string;
  repository: { full_name: string; html_url: string };
  text_matches?: Array<{ fragment: string }>;
}

async function fetchGithubCodeSearch(query: string, pat: string): Promise<{ name: string; path: string; repoUrl: string; fileUrl: string; fragment: string }[]> {
  const url = `https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=10`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Authorization': `Bearer ${pat}`,
        'Accept': 'application/vnd.github.text-match+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'recon-app/1.0',
      },
    });
    clearTimeout(timer);
    if (!resp.ok) {
      // 422 = query too complex, 403 = rate limited
      return [];
    }
    const json = await resp.json() as { items?: GithubSearchItem[] };
    const items: GithubSearchItem[] = json.items || [];
    return items.slice(0, 10).map((item) => ({
      name: item.name || '',
      path: item.path || '',
      repoUrl: item.repository?.html_url || '',
      fileUrl: item.html_url || '',
      fragment: item.text_matches?.[0]?.fragment || '',
    }));
  } catch { return []; }
}

async function fetchSerpApiResults(query: string, apiKey: string): Promise<{ title: string; url: string; snippet: string }[]> {
  const url = `https://serpapi.com/search.json?q=${encodeURIComponent(query)}&api_key=${encodeURIComponent(apiKey)}&num=10&engine=google`;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!resp.ok) return [];
    const json = await resp.json() as any;
    const organic: any[] = json.organic_results || [];
    return organic.slice(0, 10).map((r: any) => ({
      title: r.title || '',
      url: r.link || '',
      snippet: r.snippet || '',
    }));
  } catch { return []; }
}

app.post('/api/dorking', reconLimiter, async (req, res) => {
  const parse = DorkingQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const serpApiKey = process.env.SERPAPI_KEY || '';
  const hasSerpApi = !!serpApiKey;

  const rawDorks = loadDorksFile();
  if (!rawDorks.length) {
    return res.status(500).json({ error: 'dorks.txt not found or empty' });
  }

  // Substitute target domain into each dork
  const dorks = rawDorks.map(d => ({
    category: d.category,
    query: substituteDomain(d.query, target),
    googleUrl: `https://www.google.com/search?q=${encodeURIComponent(substituteDomain(d.query, target))}`,
  }));

  // If no SerpAPI key, return dorks with Google URLs only (user clicks manually)
  if (!hasSerpApi) {
    return res.json({
      target,
      total: dorks.length,
      hasSerpApi: false,
      dorks: dorks.map(d => ({ ...d, results: [] })),
    });
  }

  // With SerpAPI: stream results as NDJSON so UI updates progressively
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('Cache-Control', 'no-cache');

  try { res.write(JSON.stringify({ type: 'start', target, total: dorks.length, hasSerpApi: true }) + '\n'); } catch {}

  // Rate-limit: 1 request per second to avoid Google/SerpAPI throttling
  const DELAY_MS = 1200;
  for (let i = 0; i < dorks.length; i++) {
    const dork = dorks[i];
    if (!dork) continue;
    const results = await fetchSerpApiResults(dork.query, serpApiKey);
    const frame = {
      type: 'dork',
      index: i,
      category: dork.category,
      query: dork.query,
      googleUrl: dork.googleUrl,
      results,
      hasHits: results.length > 0,
    };
    try { res.write(JSON.stringify(frame) + '\n'); } catch { break; }
    if (i < dorks.length - 1) await new Promise(r => setTimeout(r, DELAY_MS));
  }

  try { res.write(JSON.stringify({ type: 'done', target, total: dorks.length }) + '\n'); res.end(); } catch {}
});

// ── GitHub Dorking ────────────────────────────────────────────────────────
// Reads github_dorks.txt, substitutes the target domain, and searches GitHub
// code search API using GITHUB_PAT. Streams results as NDJSON.

app.post('/api/github-dorking', reconLimiter, async (req, res) => {
  const parse = GithubDorkingQuery.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: 'Invalid payload', details: parse.error.flatten() });
  }
  const { target } = parse.data;
  const githubPat = process.env.GITHUB_PAT || '';
  if (!githubPat) {
    return res.status(500).json({ error: 'GITHUB_PAT not configured on server' });
  }

  const rawDorks = loadGithubDorksFile();
  if (!rawDorks.length) {
    return res.status(500).json({ error: 'github_dorks.txt not found or empty' });
  }

  // Substitute target domain into each dork
  const dorks = rawDorks.map(d => ({
    category: d.category,
    query: substituteGithubDomain(d.query, target),
    githubUrl: `https://github.com/search?q=${encodeURIComponent(substituteGithubDomain(d.query, target))}&type=code`,
  }));

  // Stream results as NDJSON
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('Cache-Control', 'no-cache');

  try { res.write(JSON.stringify({ type: 'start', target, total: dorks.length }) + '\n'); } catch {}

  // GitHub Search API: 10 requests/min for authenticated users (unauthenticated: 10/min)
  // We use 7s delay to stay safely under the 10/min limit
  const DELAY_MS = 7000;
  for (let i = 0; i < dorks.length; i++) {
    const dork = dorks[i];
    if (!dork) continue;
    const results = await fetchGithubCodeSearch(dork.query, githubPat);
    const frame = {
      type: 'dork',
      index: i,
      category: dork.category,
      query: dork.query,
      githubUrl: dork.githubUrl,
      results,
      hasHits: results.length > 0,
    };
    try { res.write(JSON.stringify(frame) + '\n'); } catch { break; }
    if (i < dorks.length - 1) await new Promise(r => setTimeout(r, DELAY_MS));
  }

  try { res.write(JSON.stringify({ type: 'done', target, total: dorks.length }) + '\n'); res.end(); } catch {}
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

