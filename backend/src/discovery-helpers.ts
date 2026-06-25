import * as dns from 'dns';
import { promisify } from 'util';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync, mkdirSync } from 'fs';
import path from 'path';

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
export function isValidIpString(str: string): boolean {
  const s = str.trim();
  if (ipv4Re.test(s)) {
    const parts = s.split('.');
    return parts.every((p) => {
      const n = parseInt(p, 10);
      return n >= 0 && n <= 255;
    });
  }
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(s) || s === '::1' || /^::/.test(s)) {
    return true;
  }
  return false;
}

const domainLineRe = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

export function isLikelyHostname(line: string): boolean {
  if (!line || line.includes('/') || line.includes('\\')) return false;
  if (isValidIpString(line)) return false;
  return domainLineRe.test(line);
}

export function isUnderTarget(host: string, target: string): boolean {
  const h = host.replace(/^\*\./, '').replace(/^www\./, '').toLowerCase().trim();
  const t = target.toLowerCase().trim();
  if (!h || !t) return false;
  if (h === t) return true;
  return h.endsWith('.' + t);
}

export function normalizeHostname(h: string): string {
  return h.replace(/^\*\./, '').trim().toLowerCase();
}

export async function fetchCrtShHostnames(domain: string): Promise<string[]> {
  const q = `%.${domain}`;
  const url = `https://crt.sh/?q=${encodeURIComponent(q)}&output=json`;
  const ac = new AbortController();
  // Large zones (e.g. enterprise CDNs) need a long download; 25s often aborted mid-response.
  const timer = setTimeout(() => ac.abort(), 120000);
  try {
    const res = await fetch(url, { signal: ac.signal, headers: { Accept: 'application/json' } });
    if (!res.ok) return [];
    const data = (await res.json()) as Array<{ name_value?: string }>;
    if (!Array.isArray(data)) return [];
    const out = new Set<string>();
    for (const row of data) {
      const nv = row?.name_value;
      if (typeof nv !== 'string' || !nv.trim()) continue;
      for (const part of nv.split(/\n/)) {
        const name = normalizeHostname(part);
        if (isLikelyHostname(name) && isUnderTarget(name, domain)) out.add(name);
      }
    }
    return Array.from(out);
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

type VtDomainV2 = {
  response_code?: number;
  subdomains?: string[];
  resolutions?: Array<{ ip_address?: string }>;
  detected_urls?: Array<{ url?: string }>;
};

export async function fetchVirusTotalDomain(
  domain: string,
  apiKey: string | undefined
): Promise<{ subdomains: string[]; ips: string[] }> {
  if (!apiKey?.trim()) return { subdomains: [], ips: [] };
  const url = `https://www.virustotal.com/vtapi/v2/domain/report?apikey=${encodeURIComponent(apiKey)}&domain=${encodeURIComponent(domain)}`;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 20000);
  try {
    const res = await fetch(url, { signal: ac.signal });
    if (!res.ok) return { subdomains: [], ips: [] };
    const j = (await res.json()) as VtDomainV2;
    if (j.response_code !== 1) return { subdomains: [], ips: [] };
    const subdomains: string[] = [];
    if (Array.isArray(j.subdomains)) {
      for (const s of j.subdomains) {
        const n = normalizeHostname(String(s));
        if (isLikelyHostname(n) && isUnderTarget(n, domain)) subdomains.push(n);
      }
    }
    const ips: string[] = [];
    if (Array.isArray(j.resolutions)) {
      for (const r of j.resolutions) {
        const ip = r?.ip_address?.trim();
        if (ip && isValidIpString(ip)) ips.push(ip);
      }
    }
    if (Array.isArray(j.detected_urls)) {
      for (const du of j.detected_urls) {
        try {
          if (!du?.url) continue;
          const host = new URL(du.url).hostname.replace(/^\[/, '').replace(/\]$/, '');
          if (isValidIpString(host)) ips.push(host);
          else if (isLikelyHostname(host) && isUnderTarget(host, domain)) subdomains.push(normalizeHostname(host));
        } catch {}
      }
    }
    return {
      subdomains: Array.from(new Set(subdomains)),
      ips: Array.from(new Set(ips)),
    };
  } catch {
    return { subdomains: [], ips: [] };
  } finally {
    clearTimeout(timer);
  }
}

function walkDirFiles(root: string, maxDepth: number, acc: string[]): void {
  if (maxDepth < 0 || !existsSync(root)) return;
  let st: ReturnType<typeof statSync>;
  try {
    st = statSync(root);
  } catch {
    return;
  }
  if (st.isFile()) {
    if (/\.(jsonl|json|txt)$/i.test(root)) acc.push(root);
    return;
  }
  if (!st.isDirectory()) return;
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return;
  }
  for (const name of entries) {
    if (name.startsWith('.')) continue;
    walkDirFiles(path.join(root, name), maxDepth - 1, acc);
  }
}

function extractFromBbotObject(obj: unknown, target: string, hosts: Set<string>, ips: Set<string>): void {
  if (obj === null || obj === undefined) return;
  if (typeof obj === 'string') {
    const s = obj.trim();
    if (isValidIpString(s)) ips.add(s);
    else if (isLikelyHostname(s) && isUnderTarget(normalizeHostname(s), target)) hosts.add(normalizeHostname(s));
    return;
  }
  if (Array.isArray(obj)) {
    for (const x of obj) extractFromBbotObject(x, target, hosts, ips);
    return;
  }
  if (typeof obj === 'object') {
    const o = obj as Record<string, unknown>;
    const typ = typeof o.type === 'string' ? o.type : '';
    if (typ === 'DNS_NAME' || typ === 'SUBDOMAIN') {
      const h =
        (typeof o.host === 'string' && o.host) ||
        (typeof o.data === 'object' && o.data !== null && typeof (o.data as Record<string, unknown>).host === 'string'
          ? String((o.data as Record<string, unknown>).host)
          : '') ||
        (typeof o.data === 'object' && o.data !== null && typeof (o.data as Record<string, unknown>).name === 'string'
          ? String((o.data as Record<string, unknown>).name)
          : '');
      if (h && isLikelyHostname(normalizeHostname(h)) && isUnderTarget(normalizeHostname(h), target)) {
        hosts.add(normalizeHostname(h));
      }
    }
    if (typ === 'IP_ADDRESS' || typ === 'A' || typ === 'AAAA') {
      const ip =
        (typeof o.ip === 'string' && o.ip) ||
        (typeof o.host === 'string' && isValidIpString(o.host) ? o.host : '') ||
        (typeof o.data === 'object' && o.data !== null && typeof (o.data as Record<string, unknown>).ip === 'string'
          ? String((o.data as Record<string, unknown>).ip)
          : '');
      if (ip && isValidIpString(ip.trim())) ips.add(ip.trim());
    }
    for (const k of Object.keys(o)) extractFromBbotObject(o[k], target, hosts, ips);
  }
}

/** Parse BBot scan folder (-o output): JSONL/JSON files, curated hostnames + IPs only. */
export function parseBbotOutputDirectory(scanRoot: string, target: string): { subdomains: string[]; ips: string[] } {
  const hosts = new Set<string>();
  const ips = new Set<string>();
  if (!scanRoot || !existsSync(scanRoot)) {
    return { subdomains: [], ips: [] };
  }
  const files: string[] = [];
  walkDirFiles(scanRoot, 6, files);
  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    for (const line of content.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t);
        extractFromBbotObject(obj, target, hosts, ips);
      } catch {
        const ipm = t.match(/\b((?:\d{1,3}\.){3}\d{1,3})\b/g);
        if (ipm) ipm.forEach((ip) => isValidIpString(ip) && ips.add(ip));
      }
    }
  }
  return { subdomains: Array.from(hosts).sort(), ips: Array.from(ips).sort() };
}

export async function resolveIpsForHosts(hosts: string[], limit: number): Promise<string[]> {
  const ips = new Set<string>();
  const slice = hosts.slice(0, Math.max(0, limit));
  for (const h of slice) {
    try {
      const a = await resolve4(h);
      a.forEach((ip) => ips.add(ip));
    } catch {}
    try {
      const a6 = await resolve6(h);
      a6.forEach((ip) => ips.add(ip));
    } catch {}
  }
  return Array.from(ips);
}

export type IpSourceMap = Map<string, Set<string>>;

export function addIpSource(m: IpSourceMap, ip: string, source: string): void {
  if (!isValidIpString(ip)) return;
  const key = ip.includes(':') ? ip.toLowerCase() : ip;
  if (!m.has(key)) m.set(key, new Set());
  m.get(key)!.add(source);
}

export function ipMapToRows(m: IpSourceMap): Array<{ host: string; url: string; statusCode: null; title: string; technologies: string[] }> {
  const rows: Array<{ host: string; url: string; statusCode: null; title: string; technologies: string[] }> = [];
  for (const [ip, sources] of Array.from(m.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
    const tech = Array.from(sources).sort();
    rows.push({
      host: ip,
      url: `ip://${ip}`,
      statusCode: null,
      title: 'Discovered IP',
      technologies: tech,
    });
  }
  return rows;
}

export function writeDiscoveryOutputFile(
  outDir: string,
  target: string,
  subdomains: string[],
  ips: string[],
  counts: Record<string, number>
): string {
  safeMkdir(outDir);
  const safeName = target.replace(/[^a-z0-9.-]/gi, '_');
  const outfile = path.join(outDir, `${safeName}-discovery.txt`);
  const lines: string[] = [
    `# Recon discovery bundle for ${target}`,
    `# Generated ${new Date().toISOString()}`,
    counts ? `# Counts: ${JSON.stringify(counts)}` : '',
    '',
    '## Subdomains',
    ...subdomains.sort().map((s) => s),
    '',
    '## IPs',
    ...ips.sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).map((s) => s),
    '',
  ].filter((l) => l !== '');
  writeFileSync(outfile, lines.join('\n'), 'utf8');
  return outfile;
}

function safeMkdir(p: string) {
  try {
    mkdirSync(p, { recursive: true });
  } catch {}
}
