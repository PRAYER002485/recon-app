import { useEffect, useMemo, useState } from 'react'
import './App.css'

type ReconRow = {
  url: string
  host: string
  statusCode: number | null
  title: string
  technologies: string[]
  /** Optional: used by Host Discovery (ffuf per-IP Host header fuzzing). */
  ip?: string
  size?: number | null
  words?: number | null
  lines?: number | null
  durationMs?: number | null
  /** Host Discovery: confidence that this is a real vhost vs the IP's catch-all page. */
  confidence?: 'high' | 'medium' | 'low'
  matchReason?: string
  phase?: 'ip' | 'subdomain'
  cves?: string[]
  vulnDetails?: Array<{cve: string, score: string, description: string}>
  sslInfo?: {
    isValid: boolean
    issuer: string | null
    subject: string | null
    validFrom: string | null
    validTo: string | null
    daysUntilExpiry: number | null
    signatureAlgorithm: string | null
    keySize: number | null
    san: string[] | null
    error: string | null
  }
}

type DiscoverySummary = {
  subfinder: number
  crtSh: number
  virusTotal: { hosts: number; ips: number }
  bbot: { hosts: number; ips: number }
  bbotDir: string
  outputFile: string | null
  httpxInputHosts?: number
  httpxMaxHosts?: number
}

type ReconResponse = {
  target: string
  count: number
  results: ReconRow[]
  /** Full deduped hostname inventory (subfinder + crt.sh + VT + bbot), independent of httpx. */
  mergedCount?: number
  mergedSubdomains?: string[]
  ipCount?: number
  ipResults?: ReconRow[]
  discovery?: DiscoverySummary
  /** Host discovery: IP→Host phase results */
  ipDiscoveryCount?: number
  /** Host discovery: Subdomain→IP reverse phase results */
  subdomainDiscoveryCount?: number
  /** Host discovery: number of unreachable subdomains that were reverse-probed */
  unreachableSubdomainCount?: number
  /** Host discovery: distinct hostnames that produced a genuine (non-default) hit. */
  liveHosts?: string[]
  liveIps?: string[]
  liveHostCount?: number
  liveIpCount?: number
  confidenceBreakdown?: { high: number; medium: number; low: number }
  enrichment?: {
    ptrHosts: string[]
    certHosts: string[]
    neighbourIps: string[]
    asn: { prefix: string; asn: number | null; name: string | null } | null
  }
}

type PromptInjectionRow = {
  ruleName: string
  type: string
  severity: 'low' | 'medium' | 'high'
  passed: boolean
  passRate: string
  response?: string
  evaluation?: string
  reason?: string
  failedResult?: any
  status?: string
}

type PromptInjectionResponse = {
  target: string
  count: number
  results: PromptInjectionRow[]
}

type GarakScanResponse = {
  target: string
  targetType: string
  targetName: string | null
  probes: string[]
  generations: number | null
  ok: boolean
  exitCode: number
  report?: { jsonl: string | null, html: string | null }
  digest?: any
  stdout: string
  stderr: string
  errorHint?: string | null
}

const SECTION_KEYS = ['subdomains', 'ports', 'host-discovery', 'urls', 'nmap', 'ssl', 'breach', 'headers', 'dns', 'reputation', 'buckets', 'nuclei', 'takeover', 'prompt-injection', 'garak-scan', 'dorking', 'github-dorking'] as const
type SectionKey = typeof SECTION_KEYS[number]
type SectionSnapshots = Record<SectionKey, ReconResponse | null>

function createEmptySnapshots(): SectionSnapshots {
  return SECTION_KEYS.reduce((acc, key) => {
    acc[key] = null
    return acc
  }, {} as SectionSnapshots)
}

type StatusSortOrder = 'none' | 'asc' | 'desc'

function statusCodeSortKey(code: number | null | undefined): number {
  if (code === null || code === undefined) return 100000
  const n = Number(code)
  return Number.isFinite(n) ? n : 100001
}

function sortRowsByHttpStatus(rows: ReconRow[], dir: 'asc' | 'desc'): ReconRow[] {
  return [...rows].sort((a, b) => {
    const ka = statusCodeSortKey(a.statusCode)
    const kb = statusCodeSortKey(b.statusCode)
    return dir === 'asc' ? ka - kb : kb - ka
  })
}

function statusClass(code: number | null | undefined): string {
  if (code === null || code === undefined) return ''
  if (code >= 200 && code < 300) return 'status-2xx'
  if (code >= 300 && code < 400) return 'status-3xx'
  if (code >= 400 && code < 500) return 'status-4xx'
  if (code >= 500) return 'status-5xx'
  return ''
}

function App() {
  const API_BASE = (import.meta as any).env?.VITE_API_BASE || ''
  
  // Warn if API_BASE is not configured (only in development)
  if (!API_BASE && import.meta.env?.DEV) {
    console.warn(
      '⚠️ VITE_API_BASE is not set. Create frontend/.env with: VITE_API_BASE=http://localhost:4000\n' +
      'After creating .env, restart the Vite dev server.'
    )
  }
  
  const [stage, setStage] = useState<'home' | 'workspace'>('home')
  const [activeSection, setActiveSection] = useState<SectionKey>('subdomains')
  const [target, setTarget] = useState('')
  const [breachEmail, setBreachEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ReconResponse | null>(null)
  const [promptInjectionData, setPromptInjectionData] = useState<PromptInjectionResponse | null>(null)
  const [promptInjectionConfig, setPromptInjectionConfig] = useState({
    targetUrl: '',
    yamlConfig: `name: HackTheAgent Lab
method: POST
url: https://hacktheagent.com/api/chat
headers:
  Content-Type: application/json
json:
  message: "{PAYLOAD_POSITION}"
answer_focus_hint: '"response": "{ANSWER_POSITION}"'`,
    controllerModel: 'gpt-4o',
    controllerModelType: 'openai' as 'openai' | 'anthropic' | 'ollama',
    iterations: 3,
  })
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set())
  const [expandedCves, setExpandedCves] = useState<Set<string>>(new Set())
  const [statusSort, setStatusSort] = useState<StatusSortOrder>('none')
  type HostDiscSortKey = 'statusCode' | 'size' | 'words' | 'lines'
  type HostDiscSortDir = 'none' | 'asc' | 'desc'
  const [hostDiscSort, setHostDiscSort] = useState<{ key: HostDiscSortKey, dir: HostDiscSortDir }>({
    key: 'statusCode',
    dir: 'none',
  })
  const [sectionSnapshots, setSectionSnapshots] = useState<SectionSnapshots>(() => createEmptySnapshots())
  const [reportOpen, setReportOpen] = useState(false)
  const [reportText, setReportText] = useState('')
  const [reportMeta, setReportMeta] = useState<{ target: string, generatedAt: string } | null>(null)
  const [reportGenerating, setReportGenerating] = useState(false)
  const [garakConfig, setGarakConfig] = useState({
    targetLabel: 'Gandalf API',
    // Primary mode: scan a chatbot HTTP endpoint via garak's rest.RestGenerator
    targetUrl: 'https://gandalf-api.lakera.ai/api/send-message',
    method: 'POST',
    headersJson: `{
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
  "Accept": "application/json",
  "Accept-Language": "en-US,en;q=0.5",
  "Accept-Encoding": "gzip, deflate, br",
  "Origin": "https://gandalf.lakera.ai",
  "Referer": "https://gandalf.lakera.ai/",
  "Sec-Fetch-Dest": "empty",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Site": "same-site"
}`,
    requestJson: '',
    requestFormData: `{
  "defender": "baseline",
  "prompt": "$INPUT"
}`,
    useFormData: true, // Toggle between JSON and multipart/form-data
    responseJsonField: '$.response',
    requestTimeout: 20,
    verifySsl: true,
    // Garak scan settings
    probes: 'promptinject',
    generations: 1,
    extraArgs: '',
  })
  const [garakResult, setGarakResult] = useState<GarakScanResponse | null>(null)
  const mode: 'fast' | 'full' = 'fast'

  // Dorking state
  type DorkResult = { title: string; url: string; snippet: string }
  type DorkRow = { category: string; query: string; googleUrl: string; results: DorkResult[]; hasHits: boolean }
  type DorkingData = { target: string; total: number; hasSerpApi: boolean; dorks: DorkRow[]; progress?: number; done?: boolean }
  const [dorkingData, setDorkingData] = useState<DorkingData | null>(null)
  const [dorkingLoading, setDorkingLoading] = useState(false)
  const [dorkFilter, setDorkFilter] = useState<'all' | 'hits'>('all')

  // GitHub Dorking state
  type GithubDorkResult = { name: string; path: string; repoUrl: string; fileUrl: string; fragment: string }
  type GithubDorkRow = { category: string; query: string; githubUrl: string; results: GithubDorkResult[]; hasHits: boolean }
  type GithubDorkingData = { target: string; total: number; dorks: GithubDorkRow[]; progress?: number; done?: boolean }
  const [githubDorkingData, setGithubDorkingData] = useState<GithubDorkingData | null>(null)
  const [githubDorkingLoading, setGithubDorkingLoading] = useState(false)
  const [githubDorkFilter, setGithubDorkFilter] = useState<'all' | 'hits'>('all')

  // Legacy generic cache (kept for backward compatibility)
  function getCacheKey(t: string) {
    return `recon-cache:${t}:${mode}`
  }
  function getSimpleCacheKey(t: string) {
    return `recon-cache:${t}`
  }
  function saveToCache(t: string, payload: ReconResponse) {
    const envelop = JSON.stringify({ ts: Date.now(), data: payload })
    try { sessionStorage.setItem(getCacheKey(t), envelop) } catch {}
    try { localStorage.setItem(getCacheKey(t), envelop) } catch {}
    try { sessionStorage.setItem(getSimpleCacheKey(t), envelop) } catch {}
    try { localStorage.setItem(getSimpleCacheKey(t), envelop) } catch {}
  }

  // New: per-section cache to avoid re-running on tab switch
  function getSectionCacheKey(section: SectionKey, t: string) {
    return `recon-cache:${section}:${t}:${mode}`
  }
  function loadSectionCache(section: SectionKey, t: string): ReconResponse | null {
    try {
      const key = getSectionCacheKey(section, t)
      const raw =
        sessionStorage.getItem(key) ||
        localStorage.getItem(key)
      if (!raw) return null
      const parsed = JSON.parse(raw) as { ts: number, data: ReconResponse }
      return parsed.data
    } catch { return null }
  }
  function saveSectionCache(section: SectionKey, t: string, payload: ReconResponse) {
    const envelop = JSON.stringify({ ts: Date.now(), data: payload })
    const key = getSectionCacheKey(section, t)
    try { sessionStorage.setItem(key, envelop) } catch {}
    try { localStorage.setItem(key, envelop) } catch {}
  }

  function clearReconCaches() {
    try {
      const prefixes = ['recon-cache:', 'lastTarget']
      for (const storage of [sessionStorage, localStorage]) {
        const keys: string[] = []
        for (let i = 0; i < storage.length; i++) {
          const k = storage.key(i)
          if (!k) continue
          if (prefixes.some(p => k.startsWith(p))) keys.push(k)
        }
        for (const k of keys) storage.removeItem(k)
      }
    } catch {}
  }

  function toggleCveExpansion(rowId: string) {
    const key = `cve-${rowId}`
    setExpandedCves(prev => {
      const newSet = new Set(prev)
      if (newSet.has(key)) {
        newSet.delete(key)
      } else {
        newSet.add(key)
      }
      return newSet
    })
  }

  function copyToClipboard(text: string) {
    try {
      navigator.clipboard.writeText(text)
    } catch {}
  }

  const hasReportMaterial = useMemo(() => SECTION_KEYS.some(key => !!sectionSnapshots[key]), [sectionSnapshots])

  const sortedMainResults = useMemo(() => {
    if (!data?.results) return []
    if (statusSort === 'none') return data.results
    return sortRowsByHttpStatus(data.results, statusSort)
  }, [data?.results, statusSort])

  useEffect(() => {
    setStatusSort('none')
  }, [data])

  useEffect(() => {
    if (activeSection === 'host-discovery') {
      setHostDiscSort({ key: 'statusCode', dir: 'none' })
    }
  }, [activeSection])

  useEffect(() => {
    if (!data) return
    setSectionSnapshots(prev => ({ ...prev, [activeSection]: data }))
  }, [data, activeSection])

  function cycleStatusSort() {
    setStatusSort((s) => (s === 'none' ? 'asc' : s === 'asc' ? 'desc' : 'none'))
  }

  function cycleHostDiscSort(key: HostDiscSortKey) {
    setHostDiscSort(prev => {
      if (prev.key !== key) return { key, dir: 'asc' }
      if (prev.dir === 'none') return { key, dir: 'asc' }
      if (prev.dir === 'asc') return { key, dir: 'desc' }
      return { key, dir: 'none' }
    })
  }

  function triggerWaybackPrefetch(t: string, json: ReconResponse) {
    // Use all merged subdomains — the backend will skip already-cached ones
    const subs = (json.mergedSubdomains || [])
      .concat((json.results || []).map(r => r.host).filter(Boolean))
      .filter((s, i, a) => s && a.indexOf(s) === i)
      .slice(0, 200)
    if (!subs.length) return
    fetch(`${API_BASE}/api/urls-prefetch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: t, subdomains: subs, mode }),
    }).catch(() => {})
  }

  async function runRecon() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/recon`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) {
        const msg = await resp.text()
        throw new Error(msg)
      }
      const json = await resp.json() as ReconResponse
      setData(json)
      saveToCache(target.trim(), json)
      saveSectionCache('subdomains', target.trim(), json)
      triggerWaybackPrefetch(target.trim(), json)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runPorts() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/ports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host,
          statusCode: r.statusCode ?? null,
          title: r.title || (r.port ? `:${r.port}` : ''),
          technologies: r.technologies || []
        }))
      }
      setData(shaped)
      saveSectionCache('ports', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runHostDiscovery() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/host-discovery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()

      const shaped: ReconResponse = {
        target: json.target,
        count: json.count ?? (json.results || []).length,
        mergedCount: json.mergedCount,
        ipCount: json.ipCount,
        ipResults: json.ipResults,
        ipDiscoveryCount: json.ipDiscoveryCount,
        subdomainDiscoveryCount: json.subdomainDiscoveryCount,
        unreachableSubdomainCount: json.unreachableSubdomainCount,
        liveHosts: json.liveHosts,
        liveIps: json.liveIps,
        liveHostCount: json.liveHostCount,
        liveIpCount: json.liveIpCount,
        confidenceBreakdown: json.confidenceBreakdown,
        enrichment: json.enrichment,
        results: (json.results || []).map((r: any) => ({
          url: r.url || `https://${r.ip || ''}`,
          host: r.host || '',
          ip: r.ip || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || [],
          size: typeof r.size === 'number' ? r.size : null,
          words: typeof r.words === 'number' ? r.words : null,
          lines: typeof r.lines === 'number' ? r.lines : null,
          durationMs: typeof r.durationMs === 'number' ? r.durationMs : null,
          confidence: r.confidence,
          matchReason: r.matchReason,
          phase: r.phase,
        }))
      }

      setData(shaped)
      saveSectionCache('host-discovery', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runUrlsScan() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)

    // Collect live-200 subdomains from the current recon data or section cache
    const reconData = loadSectionCache('subdomains', target.trim())
    const liveSubdomains = (reconData?.results || [])
      .filter((r: any) => r.statusCode === 200 && r.host && !r.isSubdomainHeader)
      .map((r: any) => r.host as string)
      .filter((h: string, i: number, a: string[]) => h && a.indexOf(h) === i)

    const accumulated: any[] = []

    try {
      const resp = await fetch(`${API_BASE}/api/urls-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), subdomains: liveSubdomains }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      if (!resp.body) throw new Error('No response body')

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''

        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const frame = JSON.parse(trimmed)
            if (frame.type === 'start') {
              // scan started
            } else if (frame.type === 'subdomain' && frame.urls?.length > 0) {
              // Header row for this subdomain
              accumulated.push({
                url: `https://${frame.subdomain}`,
                host: frame.subdomain,
                statusCode: null,
                title: `Subdomain: ${frame.subdomain}`,
                technologies: ['Wayback Machine', 'Historical'],
                isSubdomainHeader: true,
              })
              // URL rows
              for (const u of frame.urls as string[]) {
                try {
                  const hostname = new URL(u).hostname
                  accumulated.push({
                    url: u,
                    host: hostname,
                    statusCode: null,
                    title: 'Historical URL',
                    technologies: ['Wayback Machine', 'Historical'],
                    isSubdomainHeader: false,
                    parentSubdomain: frame.subdomain,
                  })
                } catch {}
              }
              // Update state progressively so table fills in as data arrives
              const snapshot: ReconResponse = {
                target: target.trim(),
                count: accumulated.filter((r: any) => !r.isSubdomainHeader).length,
                results: [...accumulated],
              }
              setData(snapshot)
            }
          } catch {}
        }
      }

      const final: ReconResponse = {
        target: target.trim(),
        count: accumulated.filter((r: any) => !r.isSubdomainHeader).length,
        results: accumulated,
      }
      setData(final)
      saveSectionCache('urls', target.trim(), final)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  function downloadUrlsTxt() {
    if (!data?.results?.length) return
    const lines: string[] = []
    for (const row of data.results) {
      if ((row as any).isSubdomainHeader) {
        lines.push(row.host)
      } else {
        lines.push(row.url)
      }
    }
    const content = lines.join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    const safeTarget = (data.target || 'urls').replace(/[^\w.-]+/g, '_')
    link.href = url
    link.download = `${safeTarget}_urls.txt`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  async function runNmap() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/nmap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || r.ip || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || r.openPorts || [],
          cves: r.cves || [],
          vulnDetails: r.vulnDetails || [],
        }))
      }
      setData(shaped)
      saveSectionCache('nmap', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runSSLCheck() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/ssl-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || '',
          statusCode: r.statusCode || null,
          title: r.title || '',
          technologies: r.technologies || [],
          sslInfo: r.sslInfo || null,
        }))
      }
      setData(shaped)
      saveSectionCache('ssl', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runHeadersCheck() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/headers-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || []
        }))
      }
      setData(shaped)
      saveSectionCache('headers', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runDNSHygiene() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/dns-hygiene`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || []
        }))
      }
      setData(shaped)
      saveSectionCache('dns', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runReputation() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/reputation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || []
        }))
      }
      setData(shaped)
      saveSectionCache('reputation', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runBuckets() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/cloud-buckets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const shaped: ReconResponse = {
        target: json.target,
        count: json.count,
        results: (json.results || []).map((r: any) => ({
          url: r.url || '',
          host: r.host || '',
          statusCode: typeof r.statusCode === 'number' ? r.statusCode : null,
          title: r.title || '',
          technologies: r.technologies || []
        }))
      }
      setData(shaped)
      saveSectionCache('buckets', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  // Nuclei — streaming NDJSON
  async function runNuclei() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)

    const reconData = loadSectionCache('subdomains', target.trim())
    const liveSubdomains = (reconData?.results || [])
      .filter((r: any) => r.statusCode === 200 && r.host && !r.isSubdomainHeader)
      .map((r: any) => r.host as string)
      .filter((h: string, i: number, a: string[]) => h && a.indexOf(h) === i)

    const accumulated: any[] = []
    try {
      const resp = await fetch(`${API_BASE}/api/nuclei`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), subdomains: liveSubdomains }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      if (!resp.body) throw new Error('No response body')

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const frame = JSON.parse(trimmed)
            if (frame.type === 'finding') {
              accumulated.push({
                url: frame.url || frame.host || '',
                host: frame.host || '',
                statusCode: null,
                title: `[${frame.severity?.toUpperCase()}] ${frame.name}`,
                technologies: [
                  frame.severity,
                  frame.templateId,
                  ...(frame.tags || []),
                ].filter(Boolean),
                nucleiFinding: frame,
              })
              setData({
                target: target.trim(),
                count: accumulated.length,
                results: [...accumulated],
              })
            }
          } catch {}
        }
      }

      const final: ReconResponse = { target: target.trim(), count: accumulated.length, results: accumulated }
      setData(final)
      saveSectionCache('nuclei', target.trim(), final)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  // Subdomain Takeover — streaming NDJSON
  async function runTakeover() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)

    const reconData = loadSectionCache('subdomains', target.trim())
    const allSubdomains = (reconData?.mergedSubdomains || [])
      .filter((h: string) => h && h.length > 0)

    const accumulated: any[] = []
    try {
      const resp = await fetch(`${API_BASE}/api/takeover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), subdomains: allSubdomains }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      if (!resp.body) throw new Error('No response body')

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const frame = JSON.parse(trimmed)
            if (frame.type === 'result') {
              accumulated.push({
                url: `https://${frame.subdomain}`,
                host: frame.subdomain,
                statusCode: frame.vulnerable ? 200 : null,
                title: frame.vulnerable
                  ? `⚠ VULNERABLE — ${frame.service}`
                  : frame.cname ? `Safe (${frame.service || 'unknown service'})` : 'No CNAME',
                technologies: [
                  frame.vulnerable ? 'VULNERABLE' : 'safe',
                  frame.service || '',
                  frame.cname ? `CNAME:${frame.cname}` : '',
                ].filter(Boolean),
                takeoverResult: frame,
              })
              setData({
                target: target.trim(),
                count: accumulated.length,
                results: [...accumulated],
              })
            }
          } catch {}
        }
      }

      const final: ReconResponse = { target: target.trim(), count: accumulated.length, results: accumulated }
      setData(final)
      saveSectionCache('takeover', target.trim(), final)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runDorking() {
    if (!target.trim()) return
    setDorkingLoading(true)
    setError(null)
    setDorkingData(null)
    setDorkFilter('all')
    try {
      const resp = await fetch(`${API_BASE}/api/dorking`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      })
      if (!resp.ok) throw new Error(await resp.text())

      const contentType = resp.headers.get('content-type') || ''
      // Non-streaming response (no SerpAPI key)
      if (!contentType.includes('ndjson')) {
        const json = await resp.json() as any
        setDorkingData({ target: json.target, total: json.total, hasSerpApi: false, dorks: json.dorks, done: true })
        return
      }

      // Streaming NDJSON (SerpAPI mode)
      if (!resp.body) throw new Error('No response body')
      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      const accumulated: DorkRow[] = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const frame = JSON.parse(trimmed)
            if (frame.type === 'start') {
              setDorkingData({ target: frame.target, total: frame.total, hasSerpApi: true, dorks: [], progress: 0 })
            } else if (frame.type === 'dork') {
              accumulated.push({ category: frame.category, query: frame.query, googleUrl: frame.googleUrl, results: frame.results, hasHits: frame.hasHits })
              setDorkingData(prev => prev ? { ...prev, dorks: [...accumulated], progress: frame.index + 1 } : prev)
            } else if (frame.type === 'done') {
              setDorkingData(prev => prev ? { ...prev, done: true } : prev)
            }
          } catch {}
        }
      }
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setDorkingLoading(false)
    }
  }

  async function runGithubDorking() {
    if (!target.trim()) return
    setGithubDorkingLoading(true)
    setError(null)
    setGithubDorkingData(null)
    setGithubDorkFilter('all')
    try {
      const resp = await fetch(`${API_BASE}/api/github-dorking`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      })
      if (!resp.ok) throw new Error(await resp.text())

      if (!resp.body) throw new Error('No response body')
      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      const accumulated: GithubDorkRow[] = []

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed) continue
          try {
            const frame = JSON.parse(trimmed)
            if (frame.type === 'start') {
              setGithubDorkingData({ target: frame.target, total: frame.total, dorks: [], progress: 0 })
            } else if (frame.type === 'dork') {
              accumulated.push({ category: frame.category, query: frame.query, githubUrl: frame.githubUrl, results: frame.results, hasHits: frame.hasHits })
              setGithubDorkingData(prev => prev ? { ...prev, dorks: [...accumulated], progress: frame.index + 1 } : prev)
            } else if (frame.type === 'done') {
              setGithubDorkingData(prev => prev ? { ...prev, done: true } : prev)
            }
          } catch {}
        }
      }
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setGithubDorkingLoading(false)
    }
  }

  async function runBreachCheck() {
    const email = breachEmail.trim()
    if (!email) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/breach-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const breaches: any[] = json.breaches || []
      const shaped: ReconResponse = {
        target: email,
        count: breaches.length,
        results: breaches.map((b: any) => ({
          url: '-',
          host: json.email || email,
          statusCode: null,
          title: `${b.name || 'Breach'}${b.date ? ` (${b.date})` : ''}`,
          technologies: [
            ...(b.username ? [`username:${b.username}`] : []),
            ...(b.password ? ['password:present'] : []),
            ...(b.hash ? ['hash:present'] : []),
            ...(b.domain ? [`domain:${b.domain}`] : []),
          ],
        }))
      }
      setData(shaped)
      saveSectionCache('breach', email, shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runPromptInjection() {
    const config = promptInjectionConfig
    if (!config.targetUrl.trim()) {
      setError('Target URL is required')
      return
    }
    
    if (!config.yamlConfig.trim()) {
      setError('YAML configuration is required')
      return
    }
    
    setLoading(true)
    setError(null)
    setPromptInjectionData(null)
    
    try {
      const requestBody: any = {
        target: config.targetUrl,
        httpConfigYaml: config.yamlConfig,
        controllerModel: config.controllerModel,
        controllerModelType: config.controllerModelType,
        iterations: config.iterations,
      }
      
      const resp = await fetch(`${API_BASE}/api/prompt-injection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      })
      
      if (!resp.ok) {
        const errorText = await resp.text()
        throw new Error(errorText || 'Prompt injection test failed')
      }
      
      const json = await resp.json() as PromptInjectionResponse
      setPromptInjectionData(json)
      
      // Also save to cache (convert to ReconResponse format for compatibility)
      const cacheData: ReconResponse = {
        target: json.target,
        count: json.count,
        results: json.results.map(r => ({
          url: r.ruleName,
          host: json.target,
          statusCode: r.passed ? 200 : 500,
          title: `${r.type} - ${r.severity}`,
          technologies: [r.passRate, r.evaluation || ''].filter(Boolean),
        }))
      }
      saveSectionCache('prompt-injection', config.targetUrl.trim(), cacheData)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
  }

  async function runGarakScan() {
    if (!garakConfig.targetUrl.trim()) {
      setError('Target URL is required (e.g. https://hacktheagent.com/api/chat)')
      return
    }

    setLoading(true)
    setError(null)
    setGarakResult(null)

    try {
      let headersObj: Record<string, string> = {}
      if (garakConfig.headersJson.trim()) {
        try {
          headersObj = JSON.parse(garakConfig.headersJson) as Record<string, string>
        } catch {
          throw new Error('Headers must be valid JSON (object of string->string)')
        }
      }

      let reqObj: any = null
      let formDataObj: Record<string, string> | null = null
      
      if (garakConfig.useFormData && garakConfig.requestFormData.trim()) {
        try {
          formDataObj = JSON.parse(garakConfig.requestFormData) as Record<string, string>
          // Validate that form data contains $INPUT placeholder
          const hasInput = Object.values(formDataObj).some(v => typeof v === 'string' && v.includes('$INPUT'))
          if (!hasInput) {
            throw new Error('Form data must include "$INPUT" placeholder in at least one field value')
          }
        } catch (e: any) {
          throw new Error(`Request form data must be valid JSON with "$INPUT" placeholder: ${e.message}`)
        }
      } else if (garakConfig.requestJson.trim()) {
        try {
          reqObj = JSON.parse(garakConfig.requestJson)
        } catch {
          throw new Error('Request JSON template must be valid JSON and must include "$INPUT" where the prompt should be injected')
        }
      }

      const httpTargetConfig: any = {
        uri: garakConfig.targetUrl.trim(),
        method: garakConfig.method.trim() || 'POST',
        headers: headersObj,
        responseJsonField: garakConfig.responseJsonField.trim() || '$.bot_response.response',
        requestTimeout: garakConfig.requestTimeout,
        verifySsl: garakConfig.verifySsl,
      }
      
      if (formDataObj) {
        httpTargetConfig.reqTemplateFormData = formDataObj
      } else if (reqObj) {
        httpTargetConfig.reqTemplateJsonObject = reqObj
      }

      const body: any = {
        targetLabel: garakConfig.targetLabel.trim() || undefined,
        generations: garakConfig.generations,
        httpTarget: httpTargetConfig,
      }
      if (garakConfig.targetLabel.trim()) {
        body.targetLabel = garakConfig.targetLabel.trim()
      }
      const probes = garakConfig.probes
        .split(',')
        .map(p => p.trim())
        .filter(Boolean)
      if (probes.length) {
        body.probes = probes
      }
      if (garakConfig.extraArgs.trim()) {
        body.extraArgs = garakConfig.extraArgs.trim()
      }

      const apiUrl = `${API_BASE}/api/garak-scan`
      
      // Validate API_BASE is set
      if (!API_BASE || API_BASE.trim() === '') {
        throw new Error('API_BASE is not configured. Please set VITE_API_BASE in your .env file (e.g., VITE_API_BASE=http://localhost:4000)')
      }

      const resp = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (!resp.ok) {
        const text = await resp.text()
        throw new Error(`HTTP ${resp.status}: ${text || 'Garak scan failed'}`)
      }

      const json = await resp.json() as GarakScanResponse
      setGarakResult(json)
    } catch (e: any) {
      // Provide more helpful error messages
      let errorMsg = e.message || String(e)
      
      if (errorMsg.includes('Failed to fetch') || errorMsg.includes('NetworkError') || errorMsg.includes('Network request failed')) {
        errorMsg = `Cannot connect to backend API at ${API_BASE || '(not set)'}/api/garak-scan. ` +
          `Possible causes: backend not running, wrong VITE_API_BASE, or CORS blocking. ` +
          `For local dev: ensure backend is running on port 4000 and VITE_API_BASE=http://localhost:4000 in frontend/.env`
      }
      
      setError(errorMsg)
      console.error('Garak scan error:', e)
    } finally {
      setLoading(false)
    }
  }

  function toggleRuleExpansion(ruleName: string) {
    setExpandedRules(prev => {
      const newSet = new Set(prev)
      if (newSet.has(ruleName)) {
        newSet.delete(ruleName)
      } else {
        newSet.add(ruleName)
      }
      return newSet
    })
  }

  function resolveTargetLabel() {
    return target.trim() ||
      sectionSnapshots.subdomains?.target ||
      sectionSnapshots.ports?.target ||
      sectionSnapshots.urls?.target ||
      sectionSnapshots.nmap?.target ||
      sectionSnapshots.ssl?.target ||
      sectionSnapshots.headers?.target ||
      sectionSnapshots.dns?.target ||
      sectionSnapshots.reputation?.target ||
      sectionSnapshots.buckets?.target ||
      'Not specified'
  }

  function handleGenerateReport() {
    const resolvedTarget = resolveTargetLabel()
    setReportGenerating(true)
    setTimeout(() => {
      const content = buildReconReport(resolvedTarget, sectionSnapshots)
      setReportText(content)
      setReportOpen(true)
      setReportMeta({ target: resolvedTarget, generatedAt: new Date().toISOString() })
      setReportGenerating(false)
    }, 0)
  }

  function handleCopyReport() {
    if (!reportText) return
    copyToClipboard(reportText)
  }

  function handleDownloadReport() {
    if (!reportText) return
    const meta = reportMeta || { target: resolveTargetLabel(), generatedAt: new Date().toISOString() }
    const markdown = buildDownloadableMarkdown(reportText, meta)
    const blob = new Blob([markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    const safeTarget = meta.target.replace(/[^\w.-]+/g, '_') || 'recon-report'
    const stamped = meta.generatedAt.replace(/[:]/g, '-').replace('T', '_').split('.')[0]
    link.href = url
    link.download = `${safeTarget}_${stamped}.md`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  function startSearch() {
    if (!target.trim()) return
    setStage('workspace')
    setActiveSection('subdomains')
    const params = new URLSearchParams()
    params.set('target', target.trim())
    params.set('section', 'subdomains')
    try { sessionStorage.setItem('lastTarget', target.trim()) } catch {}
    window.history.pushState(null, '', `/subdomains?${params.toString()}`)
    const cached = loadSectionCache('subdomains', target.trim())
    if (cached) setData(cached)
    if (!cached) runRecon()
  }

  // On load: read target/section from URL and optionally auto-run
  useEffect(() => {
    const { pathname, search } = window.location
    const params = new URLSearchParams(search)
    let t = params.get('target')?.trim() || ''
    const section = (params.get('section') as any as SectionKey | null) || null

    if (!t) {
      try { t = sessionStorage.getItem('lastTarget') || '' } catch {}
    }

    if (pathname.startsWith('/subdomains') || pathname.startsWith('/ports') || pathname.startsWith('/host-discovery') || pathname.startsWith('/urls') || pathname.startsWith('/nmap') || pathname.startsWith('/ssl') || pathname.startsWith('/breach') || pathname.startsWith('/headers') || pathname.startsWith('/dns') || pathname.startsWith('/reputation') || pathname.startsWith('/buckets') || pathname.startsWith('/nuclei') || pathname.startsWith('/takeover') || pathname.startsWith('/prompt-injection') || pathname.startsWith('/garak-scan') || pathname.startsWith('/dorking') || t) {
      if (t) setTarget(t)
      setStage('workspace')
      const sec = section || (pathname.startsWith('/ports') ? 'ports' : pathname.startsWith('/host-discovery') ? 'host-discovery' : pathname.startsWith('/urls') ? 'urls' : pathname.startsWith('/nmap') ? 'nmap' : pathname.startsWith('/ssl') ? 'ssl' : pathname.startsWith('/breach') ? 'breach' : pathname.startsWith('/headers') ? 'headers' : pathname.startsWith('/dns') ? 'dns' : pathname.startsWith('/reputation') ? 'reputation' : pathname.startsWith('/buckets') ? 'buckets' : pathname.startsWith('/nuclei') ? 'nuclei' : pathname.startsWith('/takeover') ? 'takeover' : pathname.startsWith('/prompt-injection') ? 'prompt-injection' : pathname.startsWith('/garak-scan') ? 'garak-scan' : pathname.startsWith('/dorking') ? 'dorking' : 'subdomains')
      setActiveSection(sec)

      if (t && sec !== 'prompt-injection') {
        // Show cached immediately if present
        const cached = loadSectionCache(sec, t)
        if (cached) {
          setData(cached)
          // If we loaded subdomains from cache, still fire prefetch so Wayback is warm
          if (sec === 'subdomains') triggerWaybackPrefetch(t, cached)
        }

        // Only run if no cache exists
        if (!cached) {
          if (sec === 'ports') runPorts()
          else if (sec === 'host-discovery') runHostDiscovery()
          else if (sec === 'urls') runUrlsScan()
          else if (sec === 'nmap') runNmap()
          else if (sec === 'ssl') runSSLCheck()
          else if (sec === 'headers') runHeadersCheck()
          else if (sec === 'dns') runDNSHygiene()
          else if (sec === 'reputation') runReputation()
          else if (sec === 'buckets') runBuckets()
          else if (sec === 'nuclei') runNuclei()
          else if (sec === 'takeover') runTakeover()
          else if (sec === 'breach') {/* wait for manual run with email */}
          else if (sec === 'dorking') runDorking()
          else runRecon()
        }
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="app">
      {stage === 'home' && (
        <div className="home">
          <h1>Sec<span>Ron</span> Dashboard</h1>
          <p>Enter a domain or IP to enumerate subdomains, ports, and tech.</p>
          <div className="homeSearch">
            <input
              className="homeInput"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="example.com, *.example.com, 1.2.3.4"
              onKeyDown={(e) => { if (e.key === 'Enter') startSearch() }}
            />
            <button className="homeBtn" onClick={startSearch} disabled={!target.trim() || loading}>
              {loading ? 'Running...' : 'Search'}
            </button>
          </div>
        </div>
      )}

      {stage === 'workspace' && (
        <div className="workspace">
          <aside className="sidebar">
            <div className="brand">SecRon</div>
            <div className="targetRow" title={target}><span className="muted">Target:</span> {target}</div>
            <nav>
              <button
                className={`navItem ${activeSection === 'subdomains' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('subdomains')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'subdomains')
                  window.history.pushState(null, '', `/subdomains?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('subdomains', t)
                    if (cached) setData(cached)
                    else runRecon()
                  }
                }}
              >
                Subdomain Discovery
              </button>

              <button
                className={`navItem ${activeSection === 'ports' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('ports')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'ports')
                  window.history.pushState(null, '', `/ports?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('ports', t)
                    if (cached) setData(cached)
                    else runPorts()
                  }
                }}
              >
                Port Scan
              </button>

              <button
                className={`navItem ${activeSection === 'host-discovery' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('host-discovery')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'host-discovery')
                  window.history.pushState(null, '', `/host-discovery?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('host-discovery', t)
                    if (cached) setData(cached)
                    else runHostDiscovery()
                  }
                }}
              >
                Host Discovery
              </button>

              <button
                className={`navItem ${activeSection === 'urls' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('urls')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'urls')
                  window.history.pushState(null, '', `/urls?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('urls', t)
                    if (cached) setData(cached)
                    else runUrlsScan()
                  }
                }}
              >
                URLs
              </button>

              <button
                className={`navItem ${activeSection === 'headers' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('headers')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'headers')
                  window.history.pushState(null, '', `/headers?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('headers', t)
                    if (cached) setData(cached)
                    else runHeadersCheck()
                  }
                }}
              >
                Headers Check
              </button>

              <button
                className={`navItem ${activeSection === 'dns' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('dns')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'dns')
                  window.history.pushState(null, '', `/dns?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('dns', t)
                    if (cached) setData(cached)
                    else runDNSHygiene()
                  }
                }}
              >
                DNS Hygiene
              </button>

              <button
                className={`navItem ${activeSection === 'nmap' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('nmap')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'nmap')
                  window.history.pushState(null, '', `/nmap?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('nmap', t)
                    if (cached) setData(cached)
                    else runNmap()
                  }
                }}
              >
                Nmap
              </button>

              <button
                className={`navItem ${activeSection === 'ssl' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('ssl')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'ssl')
                  window.history.pushState(null, '', `/ssl?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('ssl', t)
                    if (cached) setData(cached)
                    else runSSLCheck()
                  }
                }}
              >
                SSL/TLS Check
              </button>

              <button
                className={`navItem ${activeSection === 'reputation' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('reputation')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'reputation')
                  window.history.pushState(null, '', `/reputation?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('reputation', t)
                    if (cached) setData(cached)
                    else runReputation()
                  }
                }}
              >
                Reputation
              </button>

              <button
                className={`navItem ${activeSection === 'buckets' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('buckets')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'buckets')
                  window.history.pushState(null, '', `/buckets?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('buckets', t)
                    if (cached) setData(cached)
                    else runBuckets()
                  }
                }}
              >
                Open Buckets
              </button>

              <button
                className={`navItem ${activeSection === 'nuclei' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('nuclei')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'nuclei')
                  window.history.pushState(null, '', `/nuclei?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('nuclei', t)
                    if (cached) setData(cached)
                    else runNuclei()
                  }
                }}
              >
                Nuclei Scan
              </button>

              <button
                className={`navItem ${activeSection === 'takeover' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('takeover')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'takeover')
                  window.history.pushState(null, '', `/takeover?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('takeover', t)
                    if (cached) setData(cached)
                    else runTakeover()
                  }
                }}
              >
                Takeover Check
              </button>

              <button
                className={`navItem ${activeSection === 'breach' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('breach')
                  setError(null)
                  setData(null)
                  const params = new URLSearchParams()
                  params.set('section', 'breach')
                  window.history.pushState(null, '', `/breach?${params.toString()}`)
                }}
              >
                Breach Check
              </button>

              <button
                className={`navItem ${activeSection === 'prompt-injection' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('prompt-injection')
                  setError(null)
                  setData(null)
                  const params = new URLSearchParams()
                  params.set('section', 'prompt-injection')
                  window.history.pushState(null, '', `/prompt-injection?${params.toString()}`)
                }}
              >
                Prompt Injection
              </button>

              <button
                className={`navItem ${activeSection === 'garak-scan' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('garak-scan')
                  setError(null)
                  setData(null)
                  const params = new URLSearchParams()
                  params.set('section', 'garak-scan')
                  window.history.pushState(null, '', `/garak-scan?${params.toString()}`)
                }}
              >
                Garak LLM Scan
              </button>

              <button
                className={`navItem ${activeSection === 'dorking' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('dorking')
                  setError(null)
                  setData(null)
                  const params = new URLSearchParams()
                  if (target.trim()) params.set('target', target.trim())
                  params.set('section', 'dorking')
                  window.history.pushState(null, '', `/dorking?${params.toString()}`)
                  if (!dorkingData && target.trim()) runDorking()
                }}
              >
                🔍 Google Dorking
              </button>

              <button
                className={`navItem ${activeSection === 'github-dorking' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('github-dorking')
                  setError(null)
                  setData(null)
                  const params = new URLSearchParams()
                  if (target.trim()) params.set('target', target.trim())
                  params.set('section', 'github-dorking')
                  window.history.pushState(null, '', `/github-dorking?${params.toString()}`)
                  if (!githubDorkingData && target.trim()) runGithubDorking()
                }}
              >
                🐙 GitHub Dorking
              </button>
            </nav>
          </aside>

          <main className="content">
            <header className="toolbar">
              <div className="toolbarLeft">
                <button onClick={() => {
                  clearReconCaches()
                  setTarget('')
                  setData(null)
                  setError(null)
                  setStage('home')
                  window.history.pushState(null, '', '/')
                }} className="linkBtn">New Search</button>
              </div>
              <div className="toolbarRight">
                {activeSection === 'subdomains' && (
                  <button onClick={runRecon} disabled={loading}>
                    {loading ? 'Running...' : 'Run again'}
                  </button>
                )}
                {activeSection === 'ports' && (
                  <>
                    <button onClick={runPorts} disabled={loading}>
                      {loading ? 'Scanning...' : 'Run ports'}
                    </button>
                    <button
                      style={{ marginLeft: 8 }}
                      onClick={() => {
                        setActiveSection('nmap')
                        setError(null)
                        const t = target.trim()
                        const params = new URLSearchParams()
                        if (t) params.set('target', t)
                        params.set('section', 'nmap')
                        window.history.pushState(null, '', `/nmap?${params.toString()}`)
                        runNmap()
                      }}
                      disabled={loading}
                    >
                      {loading ? 'Scanning all...' : 'Port scan all subdomains'}
                    </button>
                  </>
                )}
                {activeSection === 'urls' && (
                  <>
                    <button onClick={runUrlsScan} disabled={loading}>
                      {loading ? 'Fetching URLs...' : 'Run URLs scan'}
                    </button>
                    {!loading && data?.results?.some((r: any) => !r.isSubdomainHeader) && (
                      <button onClick={downloadUrlsTxt} title="Download URLs as .txt">
                        Download URLs (.txt)
                      </button>
                    )}
                  </>
                )}
                {activeSection === 'nmap' && (
                  <button onClick={runNmap} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run nmap'}
                  </button>
                )}
                {activeSection === 'ssl' && (
                  <button onClick={runSSLCheck} disabled={loading}>
                    {loading ? 'Checking SSL...' : 'Run SSL check'}
                  </button>
                )}
                {activeSection === 'headers' && (
                  <button onClick={runHeadersCheck} disabled={loading}>
                    {loading ? 'Checking...' : 'Run headers check'}
                  </button>
                )}
                {activeSection === 'dns' && (
                  <button onClick={runDNSHygiene} disabled={loading}>
                    {loading ? 'Resolving...' : 'Run DNS hygiene'}
                  </button>
                )}
                {activeSection === 'reputation' && (
                  <button onClick={runReputation} disabled={loading}>
                    {loading ? 'Checking...' : 'Run reputation'}
                  </button>
                )}
                {activeSection === 'buckets' && (
                  <button onClick={runBuckets} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run buckets check'}
                  </button>
                )}
                {activeSection === 'nuclei' && (
                  <button onClick={runNuclei} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run Nuclei scan'}
                  </button>
                )}
                {activeSection === 'takeover' && (
                  <button onClick={runTakeover} disabled={loading}>
                    {loading ? 'Checking...' : 'Run takeover check'}
                  </button>
                )}
                {activeSection === 'breach' && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <input
                      className="homeInput"
                      style={{ maxWidth: 300 }}
                      value={breachEmail}
                      onChange={e => setBreachEmail(e.target.value)}
                      placeholder="[email protected]"
                      onKeyDown={(e) => { if (e.key === 'Enter') runBreachCheck() }}
                    />
                    <button onClick={runBreachCheck} disabled={loading || !breachEmail.trim()}>
                      {loading ? 'Checking...' : 'Check breaches'}
                    </button>
                  </div>
                )}
                {activeSection === 'prompt-injection' && (
                  <button onClick={runPromptInjection} disabled={loading || !promptInjectionConfig.targetUrl.trim()}>
                    {loading ? 'Testing...' : 'Run Prompt Injection Test'}
                  </button>
                )}
                {activeSection === 'garak-scan' && (
                  <button onClick={runGarakScan} disabled={loading || !garakConfig.targetUrl.trim()}>
                    {loading ? 'Running...' : 'Run Garak Scan'}
                  </button>
                )}
                {activeSection === 'dorking' && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <button onClick={runDorking} disabled={dorkingLoading || !target.trim()}>
                      {dorkingLoading ? `Dorking... ${dorkingData?.progress ?? 0}/${dorkingData?.total ?? '?'}` : 'Run Dorking'}
                    </button>
                    {dorkingData && !dorkingData.hasSerpApi && (
                      <span style={{ fontSize: 12, color: 'var(--muted)' }}>Set SERPAPI_KEY for live results</span>
                    )}
                    {dorkingData && (
                      <button
                        style={{ marginLeft: 4 }}
                        onClick={() => setDorkFilter(f => f === 'all' ? 'hits' : 'all')}
                      >
                        {dorkFilter === 'all' ? 'Show hits only' : 'Show all'}
                      </button>
                    )}
                  </div>
                )}
                {activeSection === 'github-dorking' && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <button onClick={runGithubDorking} disabled={githubDorkingLoading || !target.trim()}>
                      {githubDorkingLoading
                        ? `Searching... ${githubDorkingData?.progress ?? 0}/${githubDorkingData?.total ?? '?'}`
                        : 'Run GitHub Dorking'}
                    </button>
                    {githubDorkingData && (
                      <button
                        style={{ marginLeft: 4 }}
                        onClick={() => setGithubDorkFilter(f => f === 'all' ? 'hits' : 'all')}
                      >
                        {githubDorkFilter === 'all' ? 'Show hits only' : 'Show all'}
                      </button>
                    )}
                    <span style={{ fontSize: 12, color: 'var(--muted)' }}>Uses GitHub Code Search API</span>
                  </div>
                )}
                <button
                  className="reportBtn"
                  onClick={handleGenerateReport}
                  disabled={!hasReportMaterial || reportGenerating}
                >
                  {reportGenerating ? 'Building report...' : reportText ? 'Refresh report' : 'Generate report'}
                </button>
              </div>
            </header>

            {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

            {reportOpen && (
              <section className="reportPanel">
                <div className="reportPanelHeader">
                  <div>
                    <h3>Analyst Report</h3>
                    <p>Auto-generated from collected recon data</p>
                  </div>
                  <div className="reportPanelActions">
                    <button onClick={handleGenerateReport} disabled={reportGenerating}>
                      {reportGenerating ? 'Updating...' : 'Regenerate'}
                    </button>
                    <button onClick={handleCopyReport} disabled={!reportText}>
                      Copy
                    </button>
                    <button onClick={handleDownloadReport} disabled={!reportText}>
                      Download .md
                    </button>
                    <button className="linkBtn" onClick={() => setReportOpen(false)}>
                      Hide
                    </button>
                  </div>
                </div>
                <textarea
                  className="reportTextarea"
                  value={reportText}
                  readOnly
                  placeholder="Run at least one scan to populate the report."
                />
              </section>
            )}

          
            {activeSection === 'prompt-injection' && (
              <section className="results">
                <div style={{ marginBottom: 20 }}>
                  <h3 style={{ marginBottom: 16 }}>Prompt Injection Configuration</h3>
                  
                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                      Target URL (LLM Endpoint):
                    </label>
                    <input
                      style={{ 
                        width: '100%', 
                        maxWidth: '100%',
                        background: 'var(--card)', 
                        color: 'var(--text)', 
                        border: '1px solid #1f2937', 
                        borderRadius: '10px', 
                        padding: '12px 14px', 
                        fontSize: '16px',
                        fontFamily: 'inherit'
                      }}
                      value={promptInjectionConfig.targetUrl}
                      onChange={e => setPromptInjectionConfig({ ...promptInjectionConfig, targetUrl: e.target.value })}
                      placeholder="https://hacktheagent.com/api/chat"
                    />
                  </div>

                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                      YAML Configuration (must include {`{PAYLOAD_POSITION}`} placeholder):
                    </label>
                    <textarea
                      style={{ 
                        width: '100%', 
                        maxWidth: '100%',
                        minHeight: 250, 
                        background: '#0b1220',
                        color: 'var(--text)', 
                        border: '1px solid #1f2937', 
                        borderRadius: '12px', 
                        padding: '14px',
                        fontSize: '13px',
                        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                        lineHeight: '1.5',
                        resize: 'vertical',
                        outline: 'none'
                      }}
                      value={promptInjectionConfig.yamlConfig}
                      onChange={e => setPromptInjectionConfig({ ...promptInjectionConfig, yamlConfig: e.target.value })}
                      placeholder={`name: HackTheAgent Lab
method: POST
url: https://hacktheagent.com/api/chat
headers:
  Content-Type: application/json
json:
  message: "{PAYLOAD_POSITION}"
answer_focus_hint: '"response": "{ANSWER_POSITION}"'`}
                    />
                    <div style={{ marginTop: 8, fontSize: '12px', color: 'var(--muted)' }}>
                      💡 Tip: Use {`{PAYLOAD_POSITION}`} where the attack prompt should be inserted, and {`{ANSWER_POSITION}`} in answer_focus_hint to locate the response.
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
                    <div>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Controller Model Type:
                      </label>
                      <select
                        className="homeInput"
                        value={promptInjectionConfig.controllerModelType}
                        onChange={e => setPromptInjectionConfig({
                          ...promptInjectionConfig,
                          controllerModelType: e.target.value as any
                        })}
                      >
                        <option value="openai">OpenAI</option>
                        <option value="anthropic">Anthropic</option>
                        <option value="ollama">Ollama</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Controller Model:
                      </label>
                      <input
                        className="homeInput"
                        style={{ width: 200 }}
                        value={promptInjectionConfig.controllerModel}
                        onChange={e => setPromptInjectionConfig({
                          ...promptInjectionConfig,
                          controllerModel: e.target.value
                        })}
                        placeholder="gpt-4o"
                      />
                    </div>
                    <div>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Iterations:
                      </label>
                      <input
                        type="number"
                        className="homeInput"
                        style={{ width: 100 }}
                        min={1}
                        max={10}
                        value={promptInjectionConfig.iterations}
                        onChange={e => setPromptInjectionConfig({
                          ...promptInjectionConfig,
                          iterations: parseInt(e.target.value) || 3
                        })}
                      />
                    </div>
                  </div>
                </div>

                {promptInjectionData && (
                  <div style={{ marginTop: 24 }}>
                    <div className="summary">
                      <span><strong>Target:</strong> {promptInjectionData.target}</span>
                      <span><strong>Rules Tested:</strong> {promptInjectionData.count}</span>
                      <span><strong>Failed:</strong> {promptInjectionData.results.filter(r => !r.passed).length}</span>
                      <span><strong>Passed:</strong> {promptInjectionData.results.filter(r => r.passed).length}</span>
                    </div>

                    <div className="tableWrap" style={{ marginTop: 16, overflowX: 'auto' }}>
                      <table className="resultsTable prompt-injection-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                        <colgroup>
                          <col style={{ width: '15%' }} />
                          <col style={{ width: '12%' }} />
                          <col style={{ width: '10%' }} />
                          <col style={{ width: '10%' }} />
                          <col style={{ width: '10%' }} />
                          <col style={{ width: '43%' }} />
                        </colgroup>
                        <thead>
                          <tr>
                            <th>Rule Name</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Pass Rate</th>
                            <th>Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {promptInjectionData.results.map((r, i) => (
                            <>
                              <tr key={r.ruleName + i}>
                                <td>{r.ruleName}</td>
                                <td>{r.type}</td>
                                <td>
                                  <span style={{
                                    padding: '4px 8px',
                                    borderRadius: 4,
                                    fontSize: '12px',
                                    backgroundColor: r.severity === 'high' ? '#ff4444' : r.severity === 'medium' ? '#ffaa00' : '#888',
                                    color: 'white'
                                  }}>
                                    {r.severity.toUpperCase()}
                                  </span>
                                </td>
                                <td style={{ padding: '8px' }}>
                                  {r.passed ? (
                                    <span style={{ color: 'green', fontWeight: 'bold' }}>✅ PASS</span>
                                  ) : (
                                    <span style={{ color: 'red', fontWeight: 'bold' }}>❌ FAIL</span>
                                  )}
                                </td>
                                <td style={{ padding: '8px' }}>{r.passRate}</td>
                                <td style={{ padding: '8px' }}>
                                  <button
                                    className="linkBtn"
                                    onClick={() => toggleRuleExpansion(r.ruleName)}
                                    style={{ whiteSpace: 'nowrap', fontSize: '13px' }}
                                  >
                                    {expandedRules.has(r.ruleName) ? 'Hide Details' : 'Show Details'}
                                  </button>
                                </td>
                              </tr>
                              {expandedRules.has(r.ruleName) && (
                                <tr key={`${r.ruleName}-details-${i}`}>
                                  <td colSpan={6} style={{ padding: '16px', backgroundColor: 'var(--card)', borderTop: '2px solid var(--accent)' }}>
                                    <div style={{ 
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '12px',
                                      maxWidth: '100%'
                                    }}>
                                      {r.status && (
                                        <div style={{ padding: '10px', backgroundColor: '#1e3a5f', borderRadius: 6, fontSize: '13px', border: '1px solid #2d4a6f' }}>
                                          <strong style={{ color: 'var(--accent)' }}>Status:</strong>{' '}
                                          <span style={{ 
                                            color: r.status === 'fail' ? '#ff6b6b' : r.status === 'pass' ? '#51cf66' : '#ffd43b',
                                            fontWeight: 'bold',
                                            marginLeft: '8px'
                                          }}>{r.status.toUpperCase()}</span>
                                        </div>
                                      )}
                                      {r.response && (
                                        <div style={{ 
                                          padding: '12px', 
                                          backgroundColor: '#1a1a2e', 
                                          borderRadius: 6,
                                          border: '1px solid #2d2d44'
                                        }}>
                                          <strong style={{ display: 'block', marginBottom: '8px', color: 'var(--accent)' }}>Response:</strong>
                                          <div style={{ 
                                            maxHeight: '300px',
                                            overflowY: 'auto',
                                            backgroundColor: '#0d1117',
                                            padding: '12px',
                                            borderRadius: '4px',
                                            border: '1px solid #30363d',
                                            fontFamily: 'monospace',
                                            fontSize: '11px',
                                            lineHeight: '1.5',
                                            whiteSpace: 'pre-wrap',
                                            wordBreak: 'break-word',
                                            color: '#c9d1d9'
                                          }}>
                                            {r.response.length > 2000 ? (
                                              <>
                                                {r.response.substring(0, 2000)}
                                                <div style={{ color: '#8b949e', fontStyle: 'italic', marginTop: '8px' }}>
                                                  ... (truncated, {r.response.length} total characters)
                                                </div>
                                              </>
                                            ) : r.response}
                                          </div>
                                        </div>
                                      )}
                                      {r.evaluation && (
                                        <div style={{ padding: '10px', backgroundColor: '#2d2416', borderRadius: 6, fontSize: '13px', border: '1px solid #4a3a1f' }}>
                                          <strong style={{ color: '#ffd43b' }}>Evaluation:</strong>{' '}
                                          <span style={{ color: '#ffd43b', marginLeft: '8px' }}>{r.evaluation}</span>
                                        </div>
                                      )}
                                      {r.reason && (
                                        <div style={{ padding: '10px', backgroundColor: '#3d1f1f', borderRadius: 6, fontSize: '13px', border: '1px solid #5a2a2a' }}>
                                          <strong style={{ color: '#ff6b6b' }}>Reason:</strong>{' '}
                                          <span style={{ color: '#ff8787', marginLeft: '8px' }}>{r.reason}</span>
                                        </div>
                                      )}
                                      {r.failedResult && typeof r.failedResult === 'object' && (
                                        <div style={{ padding: '12px', backgroundColor: '#0d1b2a', borderRadius: 6, border: '1px solid #1b263b' }}>
                                          <strong style={{ display: 'block', marginBottom: '8px', color: 'var(--accent)' }}>Full Result:</strong>
                                          <div style={{ 
                                            maxHeight: '250px',
                                            overflowY: 'auto',
                                            backgroundColor: '#0d1117',
                                            padding: '12px',
                                            borderRadius: '4px',
                                            border: '1px solid #30363d',
                                            fontFamily: 'monospace',
                                            fontSize: '10px',
                                            lineHeight: '1.4',
                                            whiteSpace: 'pre-wrap',
                                            wordBreak: 'break-word',
                                            color: '#c9d1d9'
                                          }}>
                                            {JSON.stringify(r.failedResult, null, 2).substring(0, 3000)}
                                            {JSON.stringify(r.failedResult, null, 2).length > 3000 && (
                                              <div style={{ color: '#8b949e', fontStyle: 'italic', marginTop: '8px' }}>
                                                ... (truncated)
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {!promptInjectionData && !loading && (
                  <div className="placeholder">
                    Configure the test above and click "Run Prompt Injection Test" to start.
                  </div>
                )}

                {loading && (
                  <div className="placeholder" style={{ marginTop: 12 }}>
                    Running prompt injection tests... This may take a few minutes.
                  </div>
                )}
              </section>
            )}

            {activeSection === 'garak-scan' && (
              <section className="results">
                <div style={{ marginBottom: 20 }}>
                  <h3 style={{ marginBottom: 16 }}>Garak LLM Vulnerability Scan</h3>

                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                      Optional Target Label (HTTP endpoint / integration name):
                    </label>
                    <input
                      className="homeInput"
                      style={{ width: '100%', maxWidth: '100%' }}
                      value={garakConfig.targetLabel}
                      onChange={e => setGarakConfig({ ...garakConfig, targetLabel: e.target.value })}
                      placeholder="https://target.com/api/chat (for reference only)"
                    />
                  </div>

                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                      Target Chat Endpoint URL:
                    </label>
                    <input
                      className="homeInput"
                      style={{ width: '100%', maxWidth: '100%' }}
                      value={garakConfig.targetUrl}
                      onChange={e => setGarakConfig({ ...garakConfig, targetUrl: e.target.value })}
                      placeholder="https://hacktheagent.com/api/chat"
                    />
                    <div style={{ marginTop: 6, fontSize: '12px', color: 'var(--muted)' }}>
                      This runs garak <code>rest.RestGenerator</code> from the backend (no browser CORS/NetworkError).
                    </div>
                    {(garakConfig.targetUrl.includes('hacktheagent.com') || garakConfig.headersJson.includes('cf_clearance')) && (
                      <div style={{
                        marginTop: 12,
                        padding: 14,
                        backgroundColor: '#1a1f2e',
                        border: '2px solid #f59e0b',
                        borderRadius: 8,
                        fontSize: '13px',
                      }}>
                        <div style={{ color: '#fbbf24', fontWeight: 'bold', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span>⚠️</span>
                          <span>Cloudflare Protection Detected</span>
                        </div>
                        <div style={{ color: '#cbd5e1', lineHeight: 1.6, marginBottom: 12 }}>
                          This target uses Cloudflare's advanced bot protection. <strong>Garak REST scans will NOT work</strong> - even with correct cookies, Cloudflare blocks Python HTTP clients because it checks TLS fingerprinting and browser environment signals that cannot be replicated.
                        </div>
                        <button
                          onClick={() => setActiveSection('prompt-injection')}
                          style={{
                            padding: '10px 18px',
                            backgroundColor: '#3b82f6',
                            color: 'white',
                            border: 'none',
                            borderRadius: 6,
                            cursor: 'pointer',
                            fontSize: 13,
                            fontWeight: 'bold',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 8,
                          }}
                        >
                          → Use Prompt Injection Test (Browser Mode) Instead
                        </button>
                        <div style={{ marginTop: 8, fontSize: '11px', color: '#94a3b8', fontStyle: 'italic' }}>
                          The Prompt Injection Test uses a real browser (Playwright) which can bypass Cloudflare protection.
                        </div>
                      </div>
                    )}
                    {!garakConfig.targetUrl.includes('hacktheagent.com') && !garakConfig.headersJson.includes('cf_clearance') && (
                      <div style={{ marginTop: 8, padding: 10, backgroundColor: '#1a1f2e', border: '1px solid #3b4a5c', borderRadius: 6, fontSize: '12px', color: '#94a3b8' }}>
                        <strong style={{ color: '#fbbf24' }}>Note:</strong> For Cloudflare-protected endpoints, use the <strong>"Prompt Injection Test"</strong> feature instead (it uses promptmap with browser mode).
                      </div>
                    )}
                  </div>

                  <div style={{ marginBottom: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                    <div style={{ minWidth: 220 }}>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        HTTP Method:
                      </label>
                      <input
                        className="homeInput"
                        style={{ width: '100%' }}
                        value={garakConfig.method}
                        onChange={e => setGarakConfig({ ...garakConfig, method: e.target.value })}
                        placeholder="POST"
                      />
                    </div>

                    <div style={{ minWidth: 260 }}>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Response JSONPath:
                      </label>
                      <input
                        className="homeInput"
                        style={{ width: '100%' }}
                        value={garakConfig.responseJsonField}
                        onChange={e => setGarakConfig({ ...garakConfig, responseJsonField: e.target.value })}
                        placeholder="$.bot_response.response"
                      />
                      <div style={{ marginTop: 4, fontSize: '12px', color: 'var(--muted)' }}>
                        Garak extracts the model output from this JSONPath.
                      </div>
                    </div>

                    <div style={{ minWidth: 220 }}>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Generations:
                      </label>
                      <input
                        className="homeInput"
                        style={{ width: '100%' }}
                        type="number"
                        min={1}
                        max={20}
                        value={garakConfig.generations}
                        onChange={e => setGarakConfig({ ...garakConfig, generations: Number(e.target.value || 1) })}
                      />
                    </div>

                    <div style={{ minWidth: 260 }}>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Probes (comma separated):
                      </label>
                      <input
                        className="homeInput"
                        style={{ width: '100%' }}
                        value={garakConfig.probes}
                        onChange={e => setGarakConfig({ ...garakConfig, probes: e.target.value })}
                        placeholder="promptinject,dan,xss"
                      />
                      </div>
                  </div>

                  <div style={{ marginBottom: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    <div>
                      <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                        Headers (JSON):
                      </label>
                      <textarea
                        style={{
                          width: '100%',
                          minHeight: 140,
                          background: '#0b1220',
                          color: 'var(--text)',
                          border: '1px solid #1f2937',
                          borderRadius: 8,
                          padding: 10,
                          fontSize: 12,
                          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace',
                          lineHeight: 1.4,
                          resize: 'vertical',
                        }}
                        value={garakConfig.headersJson}
                        onChange={e => setGarakConfig({ ...garakConfig, headersJson: e.target.value })}
                      />
                      <div style={{ marginTop: 6, fontSize: '12px', color: 'var(--muted)' }}>
                        Put cookies/session tokens here. Format: <code>"Cookie": "cf_clearance=VALUE; session=VALUE"</code>.
                        <br />
                        <strong>Note:</strong> If copying from Burp/DevTools, ensure the Cookie value includes the cookie names (e.g., <code>cf_clearance=...</code> not just the value). The backend will auto-fix common formatting issues.
                      </div>
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                        <label style={{ fontWeight: 'bold', flex: 1 }}>
                          Request Body:
                        </label>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          <label style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                            <input
                              type="radio"
                              checked={!garakConfig.useFormData}
                              onChange={() => setGarakConfig({ ...garakConfig, useFormData: false })}
                              style={{ cursor: 'pointer' }}
                            />
                            JSON
                          </label>
                          <label style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                            <input
                              type="radio"
                              checked={garakConfig.useFormData}
                              onChange={() => setGarakConfig({ ...garakConfig, useFormData: true })}
                              style={{ cursor: 'pointer' }}
                            />
                            Form Data
                          </label>
                        </div>
                      </div>
                      {!garakConfig.useFormData ? (
                        <textarea
                          style={{
                            width: '100%',
                            minHeight: 140,
                            background: '#0b1220',
                            color: 'var(--text)',
                            border: '1px solid #1f2937',
                            borderRadius: 8,
                            padding: 10,
                            fontSize: 12,
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace',
                            lineHeight: 1.4,
                            resize: 'vertical',
                          }}
                          value={garakConfig.requestJson}
                          onChange={e => setGarakConfig({ ...garakConfig, requestJson: e.target.value })}
                          placeholder='{"message": "$INPUT"}'
                        />
                      ) : (
                        <textarea
                          style={{
                            width: '100%',
                            minHeight: 140,
                            background: '#0b1220',
                            color: 'var(--text)',
                            border: '1px solid #1f2937',
                            borderRadius: 8,
                            padding: 10,
                            fontSize: 12,
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace',
                            lineHeight: 1.4,
                            resize: 'vertical',
                          }}
                          value={garakConfig.requestFormData}
                          onChange={e => setGarakConfig({ ...garakConfig, requestFormData: e.target.value })}
                          placeholder='{"field1": "value", "prompt": "$INPUT"}'
                        />
                      )}
                      <div style={{ marginTop: 6, fontSize: '12px', color: 'var(--muted)' }}>
                        {!garakConfig.useFormData ? (
                          <>JSON template (must include <code>"$INPUT"</code> placeholder)</>
                        ) : (
                          <>Multipart/form-data fields (JSON format, one field must contain <code>"$INPUT"</code>)</>
                        )}
                      </div>
                    </div>
                  </div>

                  <div style={{ marginBottom: 16 }}>
                    <label style={{ display: 'block', marginBottom: 8, fontWeight: 'bold' }}>
                      Extra CLI arguments (optional, advanced):
                    </label>
                    <input
                      className="homeInput"
                      style={{ width: '100%' }}
                      value={garakConfig.extraArgs}
                      onChange={e => setGarakConfig({ ...garakConfig, extraArgs: e.target.value })}
                      placeholder="e.g. --max_attempts 50 --loglevel debug"
                    />
                  </div>

                  <div style={{ marginTop: 8, fontSize: '12px', color: 'var(--muted)' }}>
                    Garak runs on the backend and writes a JSONL report; this UI shows raw stdout/stderr plus a parsed summary when available.
                  </div>
                </div>

                {garakResult && (
                  <div style={{ marginTop: 24 }}>
                    <div className="summary">
                      <span><strong>Target:</strong> {garakResult.target}</span>
                      <span><strong>Target Type:</strong> {garakResult.targetType}</span>
                      <span><strong>Target Name:</strong> {garakResult.targetName || '-'}</span>
                      <span><strong>OK:</strong> {garakResult.ok ? 'yes' : 'no'}</span>
                      <span><strong>Exit Code:</strong> {garakResult.exitCode}</span>
                    </div>

                    {garakResult.errorHint && (
                      <div style={{
                        marginTop: 16,
                        padding: 16,
                        backgroundColor: '#1a1f2e',
                        border: '2px solid #f59e0b',
                        borderRadius: 8,
                        color: '#fbbf24',
                      }}>
                        <strong style={{ display: 'block', marginBottom: 8, fontSize: 14 }}>
                          ⚠️ Error Hint:
                        </strong>
                        <div style={{ fontSize: 13, lineHeight: 1.6, marginBottom: 12 }}>
                          {garakResult.errorHint}
                        </div>
                        {garakResult.errorHint.includes('Cloudflare') && (
                          <div style={{
                            marginTop: 12,
                            padding: 16,
                            backgroundColor: '#0f172a',
                            border: '2px solid #3b82f6',
                            borderRadius: 8,
                          }}>
                            <strong style={{ display: 'block', marginBottom: 8, color: '#60a5fa', fontSize: 14 }}>
                              💡 Solution: Use Browser-Based Testing
                            </strong>
                            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6, marginBottom: 12 }}>
                              Cloudflare's advanced bot protection <strong>cannot be bypassed</strong> with Python HTTP clients (like garak's REST generator), even with correct cookies. Cloudflare checks TLS fingerprinting, HTTP/2 characteristics, and browser environment signals.
                            </div>
                            <button
                              onClick={() => setActiveSection('prompt-injection')}
                              style={{
                                padding: '10px 20px',
                                backgroundColor: '#3b82f6',
                                color: 'white',
                                border: 'none',
                                borderRadius: 6,
                                cursor: 'pointer',
                                fontSize: 13,
                                fontWeight: 'bold',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 8,
                              }}
                            >
                              → Switch to Prompt Injection Test (Browser Mode)
                            </button>
                            <div style={{ marginTop: 8, fontSize: 11, color: '#94a3b8', fontStyle: 'italic' }}>
                              The Prompt Injection Test uses promptmap with Playwright (real browser) which can bypass Cloudflare protection.
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                      <div style={{ gridColumn: '1 / span 2' }}>
                        <h4>parsed summary (digest)</h4>
                        <textarea
                          style={{
                            width: '100%',
                            minHeight: 180,
                            background: '#0b1220',
                            color: 'var(--text)',
                            border: '1px solid #1f2937',
                            borderRadius: 8,
                            padding: 10,
                            fontSize: 12,
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace',
                            lineHeight: 1.4,
                            resize: 'vertical',
                          }}
                          value={garakResult.digest ? JSON.stringify(garakResult.digest, null, 2) : ''}
                          readOnly
                        />
                      </div>
                      <div>
                        <h4>stdout</h4>
                        <textarea
                          style={{
                            width: '100%',
                            minHeight: 260,
                            background: '#0b1220',
                            color: 'var(--text)',
                            border: '1px solid #1f2937',
                            borderRadius: 8,
                            padding: 10,
                            fontSize: 12,
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                            lineHeight: 1.4,
                            resize: 'vertical',
                          }}
                          value={garakResult.stdout || ''}
                          readOnly
                        />
                      </div>
                      <div>
                        <h4>stderr</h4>
                        <textarea
                          style={{
                            width: '100%',
                            minHeight: 260,
                            background: '#0b1220',
                            color: 'var(--text)',
                            border: '1px solid #1f2937',
                            borderRadius: 8,
                            padding: 10,
                            fontSize: 12,
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                            lineHeight: 1.4,
                            resize: 'vertical',
                          }}
                          value={garakResult.stderr || ''}
                          readOnly
                        />
                      </div>
                    </div>
                  </div>
                )}

                {!garakResult && !loading && (
                  <div className="placeholder">
                    Configure garak above and click "Run Garak Scan" to start. The full garak output will be shown here.
                  </div>
                )}

                {loading && (
                  <div className="placeholder" style={{ marginTop: 12 }}>
                    Running garak scan... This may take a while depending on probes and model latency.
                  </div>
                )}
              </section>
            )}

            {activeSection === 'host-discovery' && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>Target:</strong> {data.target}</span>
                    <span><strong>IPs:</strong> {typeof data.ipCount === 'number' ? data.ipCount : '-'}</span>
                    <span><strong>IP→Host hits:</strong> {typeof data.ipDiscoveryCount === 'number' ? data.ipDiscoveryCount : data.count}</span>
                    {typeof data.subdomainDiscoveryCount === 'number' && (
                      <span title="Unreachable subdomains re-probed against all discovered IPs">
                        <strong>Subdomain→IP hits:</strong> {data.subdomainDiscoveryCount}
                      </span>
                    )}
                    {typeof data.unreachableSubdomainCount === 'number' && (
                      <span title="Subdomains that returned 404/403/501/503 or no response, used for reverse probe">
                        <strong>Unreachable:</strong> {data.unreachableSubdomainCount}
                      </span>
                    )}
                    {typeof data.mergedCount === 'number' && (
                      <span title="Deduped merged hostname inventory used for ffuf FUZZ values">
                        <strong>Inventory:</strong> {data.mergedCount} hosts
                      </span>
                    )}
                    {typeof data.liveHostCount === 'number' && (
                      <span title="Distinct hostnames that returned a genuine (non catch-all) response">
                        <strong>Live hosts:</strong> {data.liveHostCount}
                      </span>
                    )}
                    {typeof data.liveIpCount === 'number' && (
                      <span title="Distinct IPs that served at least one real vhost">
                        <strong>Live IPs:</strong> {data.liveIpCount}
                      </span>
                    )}
                    {data.confidenceBreakdown && (
                      <span title="High = differs from the IP's default page / no default vhost. Low = looks like the catch-all.">
                        <strong>Confidence:</strong>{' '}
                        <span style={{ color: '#3fb950' }}>{data.confidenceBreakdown.high}H</span>{' / '}
                        <span style={{ color: '#d29922' }}>{data.confidenceBreakdown.medium}M</span>{' / '}
                        <span style={{ opacity: 0.6 }}>{data.confidenceBreakdown.low}L</span>
                      </span>
                    )}
                  </div>
                )}

                {data?.enrichment && (
                  (data.enrichment.ptrHosts.length > 0 ||
                   data.enrichment.certHosts.length > 0 ||
                   data.enrichment.neighbourIps.length > 0 ||
                   data.enrichment.asn) ? (
                    <div className="summary" style={{ marginTop: 8, flexWrap: 'wrap' }}>
                      {data.enrichment.asn && (
                        <span title="ASN / announced prefix the seed IPs belong to (bgpview)">
                          <strong>ASN:</strong> {data.enrichment.asn.asn ? `AS${data.enrichment.asn.asn}` : '-'}
                          {data.enrichment.asn.name ? ` (${data.enrichment.asn.name})` : ''} · {data.enrichment.asn.prefix}
                        </span>
                      )}
                      {data.enrichment.ptrHosts.length > 0 && (
                        <span title={data.enrichment.ptrHosts.join('\n')}>
                          <strong>PTR hosts:</strong> {data.enrichment.ptrHosts.length}
                        </span>
                      )}
                      {data.enrichment.certHosts.length > 0 && (
                        <span title={data.enrichment.certHosts.join('\n')}>
                          <strong>Cert SAN hosts:</strong> {data.enrichment.certHosts.length}
                        </span>
                      )}
                      {data.enrichment.neighbourIps.length > 0 && (
                        <span title={data.enrichment.neighbourIps.join('\n')}>
                          <strong>ASN neighbour IPs:</strong> {data.enrichment.neighbourIps.length}
                        </span>
                      )}
                    </div>
                  ) : null
                )}

                {loading && !data && (
                  <div className="placeholder" style={{ marginTop: 12 }}>
                    Running host discovery: IP→Host scan, then reverse Subdomain→IP probe for unreachable subdomains...
                  </div>
                )}

                {data ? (() => {
                  const UNREACHABLE_CODES = new Set([404, 403, 501, 503])
                  // Prefer the per-row `phase` tag (robust after dedupe/sort);
                  // fall back to the legacy slice-by-count for older cached data.
                  const hasPhase = data.results.some(r => r.phase === 'ip' || r.phase === 'subdomain')
                  const ipPhaseRows = hasPhase
                    ? data.results.filter(r => r.phase === 'ip')
                    : (typeof data.ipDiscoveryCount === 'number' ? data.results.slice(0, data.ipDiscoveryCount) : data.results)
                  const subPhaseRows = hasPhase
                    ? data.results.filter(r => r.phase === 'subdomain')
                    : (typeof data.ipDiscoveryCount === 'number' ? data.results.slice(data.ipDiscoveryCount) : [])

                  const sortRows = (rows: ReconRow[]) => {
                    if (hostDiscSort.dir === 'none') return rows
                    return [...rows].sort((a, b) => {
                      const key = hostDiscSort.key as keyof ReconRow
                      const av = a[key] as number | null
                      const bv = b[key] as number | null
                      const an = av ?? (hostDiscSort.dir === 'asc' ? Infinity : -Infinity)
                      const bn = bv ?? (hostDiscSort.dir === 'asc' ? Infinity : -Infinity)
                      return hostDiscSort.dir === 'asc' ? an - bn : bn - an
                    })
                  }

                  const HostDiscTable = ({ rows, emptyMsg }: { rows: ReconRow[], emptyMsg: string }) => (
                    rows.length === 0
                      ? <div className="placeholder" style={{ marginTop: 8, marginBottom: 16 }}>{emptyMsg}</div>
                      : <div className="tableWrap" style={{ marginBottom: 24 }}>
                          <table className="resultsTable host-discovery-table" style={{ tableLayout: 'fixed', width: '100%' }}>
                            <thead>
                              <tr>
                                <th>IP</th>
                                <th>Host</th>
                                <th title="High = differs from the IP's default page / no default vhost. Low = looks like the catch-all.">Conf.</th>
                                <th scope="col">
                                  <button type="button" className="sortHeaderBtn" onClick={() => cycleHostDiscSort('statusCode')} title="Sort by status code">
                                    Status<span className="sortCaret" aria-hidden>{hostDiscSort.key === 'statusCode' && hostDiscSort.dir === 'asc' ? ' ^' : hostDiscSort.key === 'statusCode' && hostDiscSort.dir === 'desc' ? ' ˅' : ''}</span>
                                  </button>
                                </th>
                                <th scope="col">
                                  <button type="button" className="sortHeaderBtn" onClick={() => cycleHostDiscSort('size')} title="Sort by Size">
                                    Size<span className="sortCaret" aria-hidden>{hostDiscSort.key === 'size' && hostDiscSort.dir === 'asc' ? ' ^' : hostDiscSort.key === 'size' && hostDiscSort.dir === 'desc' ? ' ˅' : ''}</span>
                                  </button>
                                </th>
                                <th scope="col">
                                  <button type="button" className="sortHeaderBtn" onClick={() => cycleHostDiscSort('words')} title="Sort by Words">
                                    Words<span className="sortCaret" aria-hidden>{hostDiscSort.key === 'words' && hostDiscSort.dir === 'asc' ? ' ^' : hostDiscSort.key === 'words' && hostDiscSort.dir === 'desc' ? ' ˅' : ''}</span>
                                  </button>
                                </th>
                                <th scope="col">
                                  <button type="button" className="sortHeaderBtn" onClick={() => cycleHostDiscSort('lines')} title="Sort by Lines">
                                    Lines<span className="sortCaret" aria-hidden>{hostDiscSort.key === 'lines' && hostDiscSort.dir === 'asc' ? ' ^' : hostDiscSort.key === 'lines' && hostDiscSort.dir === 'desc' ? ' ˅' : ''}</span>
                                  </button>
                                </th>
                              </tr>
                            </thead>
                            <tbody>
                              {sortRows(rows).map((r, i) => (
                                <tr key={`${r.ip || 'ip'}:${r.host || 'host'}:${i}`}
                                  className={r.statusCode !== null && UNREACHABLE_CODES.has(r.statusCode) ? 'unreachableRow' : ''}>
                                  <td className="ipAddrCell">{r.ip || '-'}</td>
                                  <td className="ipInline">{r.host || '-'}</td>
                                  <td className="ipInline" title={r.matchReason || ''}>
                                    {r.confidence
                                      ? <span style={{
                                          fontWeight: 600,
                                          color: r.confidence === 'high' ? '#3fb950' : r.confidence === 'medium' ? '#d29922' : '#8b949e',
                                        }}>{r.confidence === 'high' ? 'High' : r.confidence === 'medium' ? 'Med' : 'Low'}</span>
                                      : '-'}
                                  </td>
                                  <td className="ipInline">{r.statusCode ?? '-'}</td>
                                  <td className="ipInline">{typeof r.size === 'number' ? r.size : '-'}</td>
                                  <td className="ipInline">{typeof r.words === 'number' ? r.words : '-'}</td>
                                  <td className="ipInline">{typeof r.lines === 'number' ? r.lines : '-'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                  )

                  return (
                    <div>
                      <h3 className="subdomainTableHeading" style={{ marginTop: 16 }}>
                        IP → Host Discovery
                        <span style={{ fontWeight: 400, fontSize: 13, marginLeft: 8, opacity: 0.7 }}>
                          (each IP fuzzed with all subdomains as Host header)
                        </span>
                      </h3>
                      <HostDiscTable rows={ipPhaseRows} emptyMsg="No IP→Host matches found." />

                      <h3 className="subdomainTableHeading" style={{ marginTop: 8 }}>
                        Subdomain → IP Discovery
                        <span style={{ fontWeight: 400, fontSize: 13, marginLeft: 8, opacity: 0.7 }}>
                          (unreachable subdomains re-probed against all IPs)
                        </span>
                      </h3>
                      <HostDiscTable rows={subPhaseRows} emptyMsg="No additional hits found via reverse subdomain probe." />
                    </div>
                  )
                })() : (
                  !loading && (
                    <div className="placeholder" style={{ marginTop: 20 }}>
                      No host discovery results yet. Click "Host Discovery".
                    </div>
                  )
                )}
              </section>
            )}

            {activeSection === 'nuclei' && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>Target:</strong> {data.target}</span>
                    <span><strong>Findings:</strong> {data.count}</span>
                    <span style={{ color: 'var(--err)' }}><strong>Critical/High:</strong> {data.results.filter((r: any) => r.nucleiFinding?.severity === 'critical' || r.nucleiFinding?.severity === 'high').length}</span>
                    <span style={{ color: 'var(--warn)' }}><strong>Medium:</strong> {data.results.filter((r: any) => r.nucleiFinding?.severity === 'medium').length}</span>
                  </div>
                )}
                {loading && <div className="placeholder" style={{ marginTop: 12 }}>Nuclei scanning in progress — findings appear as they are detected...</div>}
                {data && data.results.length > 0 ? (
                  <div className="tableWrap" style={{ marginTop: 8 }}>
                    <table>
                      <thead><tr>
                        <th style={{ width: '8%' }}>Severity</th>
                        <th style={{ width: '20%' }}>Template</th>
                        <th style={{ width: '28%' }}>URL</th>
                        <th style={{ width: '44%' }}>Name / Description</th>
                      </tr></thead>
                      <tbody>
                        {data.results.map((r: any, i: number) => {
                          const f = r.nucleiFinding || {}
                          const sev = (f.severity || 'info').toLowerCase()
                          const sevColor = sev === 'critical' ? '#ff2244' : sev === 'high' ? 'var(--err)' : sev === 'medium' ? 'var(--warn)' : sev === 'low' ? '#60a5fa' : 'var(--muted)'
                          return (
                            <tr key={i}>
                              <td><span style={{ background: sevColor, color: '#000', padding: '2px 7px', borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>{sev}</span></td>
                              <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{f.templateId || '-'}</td>
                              <td>
                                <div className="urlCell">
                                  <a className="urlText" href={r.url} target="_blank" rel="noreferrer" title={r.url}>{r.url}</a>
                                  <button className="iconBtn" onClick={() => navigator.clipboard?.writeText(r.url)}>⧉</button>
                                </div>
                              </td>
                              <td>
                                <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 2 }}>{f.name || r.title}</div>
                                {f.description && <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>{f.description}</div>}
                                {f.tags?.length > 0 && (
                                  <div className="tags">{f.tags.map((t: string, j: number) => <span key={j} className="tag">{t}</span>)}</div>
                                )}
                                {f.extractedResults?.length > 0 && (
                                  <div style={{ marginTop: 4, fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--accent)', background: 'rgba(0,212,255,0.06)', padding: '4px 8px', borderRadius: 3 }}>
                                    {f.extractedResults.slice(0, 3).join(' | ')}
                                  </div>
                                )}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (!loading && <div className="placeholder">No findings yet. Click "Run Nuclei scan".</div>)}
              </section>
            )}

            {activeSection === 'takeover' && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>Target:</strong> {data.target}</span>
                    <span><strong>Checked:</strong> {data.count}</span>
                    <span style={{ color: 'var(--err)' }}><strong>Vulnerable:</strong> {data.results.filter((r: any) => r.takeoverResult?.vulnerable).length}</span>
                    <span style={{ color: 'var(--ok)' }}><strong>Safe:</strong> {data.results.filter((r: any) => !r.takeoverResult?.vulnerable).length}</span>
                  </div>
                )}
                {loading && <div className="placeholder" style={{ marginTop: 12 }}>Checking subdomains for takeover vulnerabilities...</div>}
                {data && data.results.length > 0 ? (
                  <div className="tableWrap" style={{ marginTop: 8 }}>
                    <table>
                      <thead><tr>
                        <th style={{ width: '8%' }}>Status</th>
                        <th style={{ width: '28%' }}>Subdomain</th>
                        <th style={{ width: '18%' }}>Service</th>
                        <th style={{ width: '46%' }}>Evidence / CNAME</th>
                      </tr></thead>
                      <tbody>
                        {data.results
                          .slice()
                          .sort((a: any, b: any) => (b.takeoverResult?.vulnerable ? 1 : 0) - (a.takeoverResult?.vulnerable ? 1 : 0))
                          .map((r: any, i: number) => {
                            const t = r.takeoverResult || {}
                            return (
                              <tr key={i} style={t.vulnerable ? { background: 'rgba(255,68,68,0.06)' } : {}}>
                                <td>
                                  {t.vulnerable
                                    ? <span style={{ background: 'var(--err)', color: '#fff', padding: '2px 8px', borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: 'var(--mono)' }}>VULN</span>
                                    : <span style={{ background: 'rgba(0,255,163,0.12)', color: 'var(--ok)', padding: '2px 8px', borderRadius: 3, fontSize: 10, fontWeight: 600, fontFamily: 'var(--mono)', border: '1px solid rgba(0,255,163,0.2)' }}>SAFE</span>
                                  }
                                </td>
                                <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>
                                  <a href={`https://${t.subdomain}`} target="_blank" rel="noreferrer">{t.subdomain}</a>
                                </td>
                                <td style={{ fontSize: 12 }}>{t.service || '—'}</td>
                                <td style={{ fontSize: 11, fontFamily: 'var(--mono)', color: t.vulnerable ? 'var(--err)' : 'var(--muted)' }}>{t.evidence}</td>
                              </tr>
                            )
                          })}
                      </tbody>
                    </table>
                  </div>
                ) : (!loading && <div className="placeholder">No results yet. Click "Run takeover check".</div>)}
              </section>
            )}

            {(activeSection === 'subdomains' || activeSection === 'ports' || activeSection === 'urls' || activeSection === 'nmap' || activeSection === 'ssl' || activeSection === 'breach' || activeSection === 'buckets' || activeSection === 'dns' || activeSection === 'reputation' || activeSection === 'headers') && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>{activeSection === 'breach' ? 'Email' : 'Target'}:</strong> {data.target}</span>
                    <span><strong>{activeSection === 'subdomains' ? 'Live (httpx)' : 'Entries'}:</strong> {data.count}</span>
                    {activeSection === 'subdomains' && typeof data.mergedCount === 'number' && (
                      <span title="Deduped from subfinder, crt.sh, VirusTotal, BBot">
                        <strong>Inventory:</strong> {data.mergedCount} hosts
                      </span>
                    )}
                    {activeSection === 'subdomains' && typeof data.ipCount === 'number' && (
                      <span><strong>IPs (passive/DNS):</strong> {data.ipCount}</span>
                    )}
                    {activeSection === 'urls' && (data as any).totalSubdomains && (
                      <span><strong>Subdomains:</strong> {(data as any).subdomainsWithHistory}/{(data as any).totalSubdomains} with history</span>
                    )}
                  </div>
                )}

                {activeSection === 'nmap' && loading && (
                  <div className="placeholder" style={{ marginTop: 12 }}>
                    Nmap is scanning all subdomains' IPs. This may take some time...
                  </div>
                )}

                {activeSection === 'urls' && loading && (
                  <div className="placeholder" style={{ marginTop: 12 }}>
                    Fetching historical URLs from Wayback Machine for all subdomains...
                  </div>
                )}

                {data ? (
                  <div className={activeSection === 'subdomains' ? 'subdomainsResultsStack' : undefined}>
                  {activeSection === 'subdomains' && (
                    <h3 className="subdomainTableHeading">Live hosts (httpx)</h3>
                  )}
                  <div className={activeSection === 'subdomains' ? 'tableWrap tableWrapNatural' : 'tableWrap'}>
                    <table className={`resultsTable ${activeSection}-table`}>
                      <thead>
                        <tr>
                          <th>{activeSection === 'breach' ? 'Record' : 'URL'}</th>
                          <th scope="col">
                            <button
                              type="button"
                              className="sortHeaderBtn"
                              onClick={cycleStatusSort}
                              title="Sort by status code (click: ascending ^, descending ˅, then original order)"
                            >
                              Status
                              <span className="sortCaret" aria-hidden>
                                {statusSort === 'asc' ? ' ^' : statusSort === 'desc' ? ' ˅' : ''}
                              </span>
                            </button>
                          </th>
                          <th>Title</th>
                          <th>Technologies</th>
                          {activeSection === 'nmap' && (<th>Found CVEs</th>)}
                          {activeSection === 'ssl' && (<th>SSL Details</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {sortedMainResults.map((r, i) => {
                          const rowCves = deriveRowCves(r)
                          return (
                            <tr key={r.url + i} className={(r as any).isSubdomainHeader ? 'subdomain-header' : ''}>
                            <td>
                              {(r as any).isSubdomainHeader ? (
                                <strong style={{ color: 'var(--accent)', fontSize: '14px' }}>{r.host}</strong>
                              ) : activeSection === 'breach' ? (
                                <div className="urlCell">
                                  <span className="urlText" title={r.title}>{r.title}</span>
                                </div>
                              ) : (
                                <div className="urlCell">
                                  <a className="urlText" href={r.url} target="_blank" rel="noreferrer" title={r.url}>{r.url}</a>
                                  <div className="urlActions">
                                    <button className="iconBtn" title="Copy URL" onClick={() => copyToClipboard(r.url)}>⧉</button>
                                    <a className="iconBtn link" href={r.url} target="_blank" rel="noreferrer" title="Open in new tab">↗</a>
                                  </div>
                                </div>
                              )}
                            </td>
                            <td><span className={statusClass(r.statusCode)}>{r.statusCode ?? '-'}</span></td>
                            <td>{r.title || '-'}</td>
                            <td>
                              {r.technologies && r.technologies.length > 0 ? (
                                <div className="tags">
                                  {r.technologies.map((t, j) => (
                                    <span className="tag" key={t + j}>{t}</span>
                                  ))}
                                </div>
                              ) : '-'}
                            </td>
                            {activeSection === 'nmap' && (
                              <td>
                                {r.vulnDetails && r.vulnDetails.length > 0 ? (
                                  <div className="vuln-details">
                                    {(expandedCves.has(`cve-${r.url}`) ? r.vulnDetails : r.vulnDetails.slice(0, 5)).map((v, j) => (
                                      <div key={v.cve + j} className="vuln-item">
                                        <span className="cve-tag">{v.cve}</span>
                                        <span className="score">({v.score})</span>
                                        <div className="description">{v.description}</div>
                                      </div>
                                    ))}
                                    {r.vulnDetails.length > 5 && (
                                      <div 
                                        className="more-vulns" 
                                        onClick={() => toggleCveExpansion(r.url)}
                                        style={{ cursor: 'pointer' }}
                                      >
                                        {expandedCves.has(`cve-${r.url}`) 
                                          ? 'Show less' 
                                          : `+${r.vulnDetails.length - 5} more`
                                        }
                                      </div>
                                    )}
                                  </div>
                                ) : rowCves.length > 0 ? (
                                  <div className="tags">
                                    {rowCves.map((c, j) => (
                                      <span className="tag" key={c + j}>{c}</span>
                                    ))}
                                  </div>
                                ) : '-'}
                              </td>
                            )}
                            {activeSection === 'ssl' && (
                              <td>
                                {r.sslInfo ? (
                                  <div className="ssl-details">
                                    <div className="ssl-status">
                                      <span className={`ssl-badge ${r.sslInfo.isValid ? 'valid' : 'invalid'}`}>
                                        {r.sslInfo.isValid ? 'Valid' : 'Invalid'}
                                      </span>
                                    </div>
                                    {r.sslInfo.isValid ? (
                                      <div className="ssl-info">
                                        <div><strong>Issuer:</strong> {r.sslInfo.issuer || 'Unknown'}</div>
                                        <div><strong>Subject:</strong> {r.sslInfo.subject || 'Unknown'}</div>
                                        <div><strong>Expires:</strong> {r.sslInfo.daysUntilExpiry !== null ? `${r.sslInfo.daysUntilExpiry} days` : 'Unknown'}</div>
                                        <div><strong>Algorithm:</strong> {r.sslInfo.signatureAlgorithm || 'Unknown'}</div>
                                        <div><strong>Key Size:</strong> {r.sslInfo.keySize ? `${r.sslInfo.keySize} bits` : 'Unknown'}</div>
                                        {r.sslInfo.san && r.sslInfo.san.length > 0 && (
                                          <div><strong>SAN:</strong> {r.sslInfo.san.length} domains</div>
                                        )}
                                      </div>
                                    ) : (
                                      <div className="ssl-error">
                                        <strong>Error:</strong> {r.sslInfo.error || 'No certificate found'}
                                      </div>
                                    )}
                                  </div>
                                ) : '-'}
                              </td>
                            )}
                          </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>

                  {activeSection === 'subdomains' && data.ipResults && data.ipResults.length > 0 && (
                    <>
                      <h3 className="ipTableHeading">Discovered IP addresses</h3>
                      <p className="ipTableHint">Passive sources (VirusTotal, BBot file, DNS resolution of merged hosts). Lists are written together in <code className="ipInline">{data.discovery?.outputFile || 'recon-output/'}</code></p>
                      <div className="tableWrap tableWrapNatural">
                        <table className="resultsTable subdomains-table ip-discovery-table">
                          <thead>
                            <tr>
                              <th>Address</th>
                              <th>Status</th>
                              <th>Title</th>
                              <th>Sources</th>
                            </tr>
                          </thead>
                          <tbody>
                            {data.ipResults.map((r, ii) => (
                              <tr key={r.host + ii}>
                                <td>
                                  <div className="urlCell">
                                    <code className="urlText ipAddrCell">{r.host}</code>
                                    <div className="urlActions">
                                      <button className="iconBtn" title="Copy IP" onClick={() => copyToClipboard(r.host)}>⧉</button>
                                    </div>
                                  </div>
                                </td>
                                <td>{r.statusCode ?? '—'}</td>
                                <td>{r.title || '—'}</td>
                                <td>
                                  {r.technologies && r.technologies.length > 0 ? (
                                    <div className="tags">
                                      {r.technologies.map((t, j) => (
                                        <span className="tag" key={t + j}>{t}</span>
                                      ))}
                                    </div>
                                  ) : '—'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                  </div>
                ) : (
                  !loading && <div className="placeholder">Click "Run again" to populate results.</div>
                )}
              </section>
            )}

            {activeSection === 'dorking' && (
              <section className="reconSection">
                <h2>Google Dorking</h2>
                <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 12 }}>
                  {dorkingData?.hasSerpApi
                    ? `Live results via SerpAPI — ${dorkingData.dorks.filter(d => d.hasHits).length} dorks with hits out of ${dorkingData.total}`
                    : 'Click each dork to search on Google. Set SERPAPI_KEY env var to fetch live results automatically.'}
                  {dorkingLoading && dorkingData && ` (${dorkingData.progress ?? 0}/${dorkingData.total} processed...)`}
                </p>
                {dorkingLoading && !dorkingData && <div className="placeholder">Loading dorks...</div>}
                {!dorkingLoading && !dorkingData && (
                  <div className="placeholder">Click "Run Dorking" to generate Google dork queries for {target}.</div>
                )}
                {dorkingData && dorkingData.dorks.length > 0 && (() => {
                  const visibleDorks = dorkFilter === 'hits'
                    ? dorkingData.dorks.filter(d => d.hasHits)
                    : dorkingData.dorks
                  return (
                    <div className="tableWrap">
                      <table className="resultsTable">
                        <thead>
                          <tr>
                            <th style={{ width: 140 }}>Category</th>
                            <th>Dork Query</th>
                            <th style={{ width: 80 }}>Search</th>
                            {dorkingData.hasSerpApi && <th>Results</th>}
                          </tr>
                        </thead>
                        <tbody>
                          {visibleDorks.map((dork, i) => (
                            <tr key={i} style={dork.hasHits ? { background: 'rgba(0,255,163,0.04)' } : undefined}>
                              <td>
                                <span className="tag" style={{ fontSize: 11 }}>{dork.category}</span>
                              </td>
                              <td>
                                <div className="urlCell">
                                  <code className="urlText" style={{ fontSize: 12, wordBreak: 'break-all' }}>{dork.query}</code>
                                  <div className="urlActions">
                                    <button className="iconBtn" title="Copy dork" onClick={() => copyToClipboard(dork.query)}>⧉</button>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <a
                                  className="iconBtn link"
                                  href={dork.googleUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  title="Search on Google"
                                  style={{ fontSize: 13 }}
                                >
                                  ↗ Google
                                </a>
                              </td>
                              {dorkingData.hasSerpApi && (
                                <td>
                                  {dork.results.length === 0 ? (
                                    <span style={{ color: 'var(--muted)', fontSize: 12 }}>No results</span>
                                  ) : (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                                      {dork.results.map((r, j) => (
                                        <div key={j} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
                                          <a href={r.url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: 12, display: 'block' }}>{r.title || r.url}</a>
                                          {r.snippet && <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>{r.snippet}</div>}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                </td>
                              )}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                })()}
              </section>
            )}

            {activeSection === 'github-dorking' && (
              <section className="reconSection">
                <h2>GitHub Dorking</h2>
                <p style={{ color: 'var(--muted)', fontSize: 13, marginBottom: 12 }}>
                  {githubDorkingData
                    ? `GitHub Code Search — ${githubDorkingData.dorks.filter(d => d.hasHits).length} dorks with hits out of ${githubDorkingData.total}`
                    : 'Searches GitHub code for secrets, credentials, and sensitive data related to the target.'}
                  {githubDorkingLoading && githubDorkingData && ` (${githubDorkingData.progress ?? 0}/${githubDorkingData.total} processed...)`}
                </p>
                {githubDorkingLoading && !githubDorkingData && <div className="placeholder">Searching GitHub...</div>}
                {!githubDorkingLoading && !githubDorkingData && (
                  <div className="placeholder">Click "Run GitHub Dorking" to search GitHub code for {target}.</div>
                )}
                {githubDorkingData && githubDorkingData.dorks.length > 0 && (() => {
                  const visibleDorks = githubDorkFilter === 'hits'
                    ? githubDorkingData.dorks.filter(d => d.hasHits)
                    : githubDorkingData.dorks
                  return (
                    <div className="tableWrap">
                      <table className="resultsTable">
                        <thead>
                          <tr>
                            <th style={{ width: 160 }}>Category</th>
                            <th>Dork Query</th>
                            <th style={{ width: 90 }}>Search</th>
                            <th>Results</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visibleDorks.map((dork, i) => (
                            <tr key={i} style={dork.hasHits ? { background: 'rgba(0,255,163,0.04)' } : undefined}>
                              <td>
                                <span className="tag" style={{ fontSize: 11 }}>{dork.category}</span>
                              </td>
                              <td>
                                <div className="urlCell">
                                  <code className="urlText" style={{ fontSize: 11, wordBreak: 'break-all' }}>{dork.query}</code>
                                  <div className="urlActions">
                                    <button className="iconBtn" title="Copy dork" onClick={() => copyToClipboard(dork.query)}>⧉</button>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <a
                                  className="iconBtn link"
                                  href={dork.githubUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  title="Search on GitHub"
                                  style={{ fontSize: 13 }}
                                >
                                  ↗ GitHub
                                </a>
                              </td>
                              <td>
                                {dork.results.length === 0 ? (
                                  <span style={{ color: 'var(--muted)', fontSize: 12 }}>No results</span>
                                ) : (
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    {dork.results.map((r, j) => (
                                      <div key={j} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 6 }}>
                                        <div style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap' }}>
                                          <a href={r.fileUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600 }}>
                                            {r.path || r.name}
                                          </a>
                                          <a href={r.repoUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--muted)', fontSize: 11 }}>
                                            {r.repoUrl.replace('https://github.com/', '')}
                                          </a>
                                        </div>
                                        {r.fragment && (
                                          <pre style={{ color: 'var(--muted)', fontSize: 10, marginTop: 3, whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: 'rgba(0,0,0,0.2)', padding: '4px 6px', borderRadius: 4 }}>
                                            {r.fragment.slice(0, 300)}
                                          </pre>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                })()}
              </section>
            )}
          </main>
        </div>
      )}

      <footer>
        <span></span>
      </footer>
    </div>
  )
}

function buildReconReport(targetLabel: string, snapshots: SectionSnapshots): string {
  const sections = [
    buildScopeSection(targetLabel, snapshots),
    buildAssetInventorySection(snapshots),
    buildUsefulInsightsSection(snapshots),
    buildTechnologySection(snapshots),
    buildMechanismSection(snapshots),
    buildApiSurfaceSection(snapshots),
    buildCompensatingControlSection(snapshots),
    buildAttackVectorSection(snapshots),
    buildClientSideSection(snapshots),
    buildIdorSection(snapshots),
    buildFileUploadSection(snapshots),
    buildThirdPartySection(snapshots),
    buildDataExposureSection(snapshots),
    buildInfrastructureSection(snapshots),
  ]

  return sections.filter(Boolean).join('\n\n').trim() || 'No report data available yet. Run at least one module.'
}

function buildScopeSection(targetLabel: string, snapshots: SectionSnapshots): string {
  const subdomainHosts = gatherHostsFromSection(snapshots.subdomains)
  const portRows = getRenderableRows(snapshots.ports)
  const nmapRows = getRenderableRows(snapshots.nmap)
  const bucketRows = getRenderableRows(snapshots.buckets)
  const scopeLines = [
    `- Primary target: ${targetLabel}`,
    `- Hosts enumerated: ${subdomainHosts.length}`,
    `- Services/ports inspected: ${portRows.length}`,
    `- Vulnerability scan coverage: ${nmapRows.length ? `${nmapRows.length} assets` : 'pending'}`,
    `- Storage buckets detected: ${bucketRows.length}`,
  ]
  return `## SCOPE\n${scopeLines.join('\n')}`
}

function buildAssetInventorySection(snapshots: SectionSnapshots): string {
  const subdomainHosts = gatherHostsFromSection(snapshots.subdomains)
  const bucketRows = getRenderableRows(snapshots.buckets)
  const sslRows = getRenderableRows(snapshots.ssl)
  const assets: string[] = []

  if (subdomainHosts.length) {
    subdomainHosts.slice(0, 12).forEach((host, idx) => {
      assets.push(`- ${idx + 1}. ${host}`)
    })
    if (subdomainHosts.length > 12) assets.push(`- ... +${subdomainHosts.length - 12} additional hosts`)
  } else {
    assets.push('- No subdomain inventory recorded yet.')
  }

  if (bucketRows.length) {
    const buckets = bucketRows.map(r => r.url || r.title || r.host || 'Bucket').slice(0, 6)
    assets.push(`- Buckets: ${formatTopList(buckets, 6)}`)
  }

  if (sslRows.length) {
    const issuers = dedupeArray(
      sslRows
        .map(r => r.sslInfo?.issuer)
        .filter((issuer): issuer is string => !!issuer)
    )
    if (issuers.length) assets.push(`- Certificate issuers: ${formatTopList(issuers, 4)}`)
  }

  return `## ASSET INVENTORY\n${assets.join('\n')}`
}

function buildUsefulInsightsSection(snapshots: SectionSnapshots): string {
  const insights: string[] = []
  const subdomainHosts = gatherHostsFromSection(snapshots.subdomains)
  const portRows = getRenderableRows(snapshots.ports)
  const sslRows = getRenderableRows(snapshots.ssl)
  const breachCount = snapshots.breach?.count ?? 0

  if (subdomainHosts.length) {
    insights.push(`[i] Enumerated ${subdomainHosts.length} unique hosts (${formatTopList(subdomainHosts, 4)})`)
  }

  if (portRows.length) {
    const riskyPorts = portRows
      .map(r => extractPortFromRow(r))
      .filter((port): port is number => port !== null && [21, 22, 23, 80, 443, 445, 3389, 3306, 5432].includes(port))
    if (riskyPorts.length) {
      insights.push(`[i] High-value ports exposed: ${dedupeArray(riskyPorts.map(String)).join(', ')}`)
    } else {
      insights.push(`[i] ${portRows.length} listening services observed (sample: ${formatTopList(portRows.map(r => r.title || r.url).filter(Boolean), 4)})`)
    }
  }

  if (sslRows.length) {
    const expiring = sslRows.filter(r => typeof r.sslInfo?.daysUntilExpiry === 'number' && (r.sslInfo?.daysUntilExpiry ?? 0) <= 30)
    if (expiring.length) insights.push(`[i] ${expiring.length} certificates expire within 30 days (e.g., ${formatTopList(expiring.map(r => r.host || r.url), 3)})`)
  }

  if (breachCount) {
    insights.push(`[i] Breach monitor reports ${breachCount} historical exposures for ${snapshots.breach?.target}`)
  }

  if (!insights.length) insights.push('[i] No enriched insights yet. Run more modules to populate this section.')

  return `## USEFUL INSIGHT\n${insights.join('\n')}`
}

function buildTechnologySection(snapshots: SectionSnapshots): string {
  const techCounts = new Map<string, number>()
  SECTION_KEYS.forEach(key => {
    const rows = getRenderableRows(snapshots[key])
    rows.forEach(row => {
      row.technologies?.forEach(tech => {
        const label = tech.trim()
        if (!label) return
        techCounts.set(label, (techCounts.get(label) || 0) + 1)
      })
    })
  })

  const topTechs = Array.from(techCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tech, count]) => `- ${tech} (${count})`)

  return `## TECHNOLOGY FINGERPRINTS\n${topTechs.length ? topTechs.join('\n') : '- No technology fingerprints captured yet.'}`
}

function buildMechanismSection(snapshots: SectionSnapshots): string {
  const urlRows = getRenderableRows(snapshots.urls)
  const headerRows = getRenderableRows(snapshots.headers)
  const hostMap = new Map<string, ReconRow[]>()

  urlRows.forEach(row => {
    const host = resolveHost(row)
    if (!host) return
    if (!hostMap.has(host)) hostMap.set(host, [])
    hostMap.get(host)?.push(row)
  })

  const blocks = Array.from(hostMap.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 5)
    .map(([host, rows]) => {
      const endpoints = rows.slice(0, 3).map(row => {
        const parsed = safeParseUrl(row.url)
        const path = parsed?.pathname || row.url || row.title || '/'
        const params = extractQueryParams(parsed)
        const headerHints = collectHeaderHints(host, headerRows)
        return `\t- ${path}\t[body params] ${params.length ? params.join(', ') : 'none observed'}\t[cookies or headers required to perform actions] ${headerHints}`
      })
      return `[i] ${host}\n${endpoints.join('\n')}`
    })

  return `## MECHANISM OF DOMAINS\n${blocks.length ? blocks.join('\n') : 'No URL intelligence collected yet.'}`
}

function buildApiSurfaceSection(snapshots: SectionSnapshots): string {
  const urlRows = getRenderableRows(snapshots.urls)
  const apiRows = urlRows.filter(row => {
    const parsed = safeParseUrl(row.url)
    const value = (parsed?.pathname || row.url || '').toLowerCase()
    return /\/api|\/v\d|graphql|rest|soap/.test(value)
  })

  if (!apiRows.length) return '## API SURFACE SUMMARY\n- No explicit API endpoints enumerated yet.'

  const lines = apiRows.slice(0, 6).map(row => {
    const parsed = safeParseUrl(row.url)
    const host = resolveHost(row)
    const path = parsed?.pathname || row.url
    const params = extractQueryParams(parsed)
    return `- ${host}${path} (status ${row.statusCode ?? '-'}) params:${params.length ? ' ' + params.join(', ') : ' none'}`
  })

  if (apiRows.length > 6) lines.push(`- ... +${apiRows.length - 6} additional API endpoints`)

  return `## API SURFACE SUMMARY\n${lines.join('\n')}`
}

function buildCompensatingControlSection(snapshots: SectionSnapshots): string {
  const headerRows = getRenderableRows(snapshots.headers)
  const signals = summarizeHeaderSignals(headerRows)
  return [
    '## COMPENSATING CONTROL',
    `\t- Cookieflag ${signals.cookieFlag}`,
    `\t- Browser security header ${signals.browserHeaders}`,
    `\t- WAF ${signals.waf}`,
    `\t- CSP ${signals.csp}`,
    `\t- Client side encoding ${signals.clientEncoding}`,
    `\t- Server side encoding ${signals.serverEncoding}`,
  ].join('\n')
}

function buildAttackVectorSection(snapshots: SectionSnapshots): string {
  const nmapRows = getRenderableRows(snapshots.nmap)
  const portRows = getRenderableRows(snapshots.ports)
  const bucketRows = getRenderableRows(snapshots.buckets)
  const breachCount = snapshots.breach?.count ?? 0

  const blocks: string[] = []

  const vulnRows = nmapRows.filter(row => {
    const rowCves = deriveRowCves(row)
    return (row.vulnDetails && row.vulnDetails.length > 0) || rowCves.length > 0
  })
  if (vulnRows.length) {
    const entries = vulnRows.slice(0, 3).map(row => {
      const labels = row.vulnDetails && row.vulnDetails.length > 0
        ? row.vulnDetails.slice(0, 2).map(v => v.cve)
        : deriveRowCves(row).slice(0, 3)
      return `\t[+] ${row.host || row.url}: ${labels.join(', ') || 'CVE detected'}`
    })
    blocks.push(`[i] Service CVEs and outdated daemons\n${entries.join('\n')}`)
  }

  const riskyPorts = portRows
    .map(r => ({ row: r, port: extractPortFromRow(r) }))
    .filter(item => item.port !== null && [21, 22, 23, 445, 3389, 3306, 5432].includes(item.port as number))
  if (riskyPorts.length) {
    const entries = riskyPorts.slice(0, 3).map(item => `\t[+] ${item.row.host || item.row.url}: tcp/${item.port}`)
    blocks.push(`[i] Administrative ports exposed\n${entries.join('\n')}`)
  }

  if (bucketRows.length) {
    const entries = bucketRows.slice(0, 3).map(row => `\t[+] ${row.url || row.title || row.host}`)
    blocks.push(`[i] Public cloud storage or object listings\n${entries.join('\n')}`)
  }

  if (breachCount) {
    blocks.push(`[i] Account takeover context\n\t[+] ${breachCount} historical breach indicators linked to ${snapshots.breach?.target}`)
  }

  if (!blocks.length) blocks.push('[i] Awaiting additional telemetry to propose prioritized attack vectors.')

  return `## ATTACKING VECTOR\n${blocks.join('\n')}`
}

function buildClientSideSection(snapshots: SectionSnapshots): string {
  const headerRows = getRenderableRows(snapshots.headers)
  const urlRows = getRenderableRows(snapshots.urls)
  const signals = summarizeHeaderSignals(headerRows)
  const lines: string[] = []

  if (signals.csp === 'NOT OBSERVED' || signals.browserHeaders === 'NOT OBSERVED') {
    lines.push('- CSP or modern browser hardening missing on sampled endpoints.')
  }

  const reflectiveParams = urlRows.filter(row => {
    const value = (row.url || '').toLowerCase()
    return ['callback', 'redirect', 'return', 'lang', 'template', 'html', 'content'].some(keyword => value.includes(keyword))
  })
  if (reflectiveParams.length) {
    lines.push(`- Potential reflective parameters: ${formatTopList(reflectiveParams.map(r => r.url || r.title).filter(Boolean), 4)}`)
  }

  if (!lines.length) lines.push('- No client-side injection clues detected yet.')

  return `## CLIENT SIDE INJECTION NOTES\n${lines.join('\n')}`
}

function buildIdorSection(snapshots: SectionSnapshots): string {
  const urlRows = getRenderableRows(snapshots.urls)
  const candidates = urlRows.filter(row => {
    const value = (row.url || '').toLowerCase()
    return /(account|user|profile|invoice|order|tenant|org|uid|customer)/.test(value)
  })

  if (!candidates.length) {
    return `## IDOR Notes\n\t## ACCOUNT 1 ->\n\t\t- No potential IDOR parameters detected yet.`
  }

  const blocks = candidates.slice(0, 4).map((row, idx) => {
    return `\t## ACCOUNT ${idx + 1} ->\n\t\t- ${row.url || row.title || 'Endpoint'}`
  })

  return `## IDOR Notes\n${blocks.join('\n')}`
}

function buildFileUploadSection(snapshots: SectionSnapshots): string {
  const urlRows = getRenderableRows(snapshots.urls)
  const uploaders = urlRows.filter(row => /upload|import|attachment|media/.test((row.url || '').toLowerCase()))

  if (!uploaders.length) return '## FILE UPLOAD\n- No file handling endpoints observed yet.'

  const lines = uploaders.slice(0, 5).map(row => `- ${row.url || row.title} (status ${row.statusCode ?? '-'})`)
  if (uploaders.length > 5) lines.push(`- ... +${uploaders.length - 5} additional upload endpoints`)

  return `## FILE UPLOAD\n${lines.join('\n')}`
}

function buildThirdPartySection(snapshots: SectionSnapshots): string {
  const subdomainHosts = gatherHostsFromSection(snapshots.subdomains)
  const techStrings = SECTION_KEYS.flatMap(key => {
    const rows = getRenderableRows(snapshots[key])
    return rows.flatMap(row => row.technologies || [])
  })
  const signals = [...subdomainHosts, ...techStrings.map(t => t.toLowerCase())]
  const keywords = [
    { key: 'cloudflare', label: 'Cloudflare CDN/WAF' },
    { key: 'akamai', label: 'Akamai CDN' },
    { key: 'fastly', label: 'Fastly CDN' },
    { key: 'azure', label: 'Azure services' },
    { key: 'amazonaws', label: 'AWS services' },
    { key: 'googleapis', label: 'Google Cloud services' },
    { key: 'stripe', label: 'Stripe payments' },
    { key: 'paypal', label: 'PayPal integrations' },
    { key: 'auth0', label: 'Auth0 authentication' },
    { key: 'okta', label: 'Okta SSO' },
    { key: 'zendesk', label: 'Zendesk support' },
    { key: 'salesforce', label: 'Salesforce/CRM integrations' },
  ]

  const matches = keywords
    .filter(item => signals.some(signal => signal.toLowerCase().includes(item.key)))
    .map(item => `- ${item.label}`)

  return `## THIRD-PARTY INTEGRATIONS\n${matches.length ? matches.join('\n') : '- No explicit third-party integrations fingerprinted yet.'}`
}

function buildDataExposureSection(snapshots: SectionSnapshots): string {
  const urlRows = getRenderableRows(snapshots.urls)
  const sensitive = urlRows.filter(row => /(invoice|billing|payment|ticket|customer|profile|credential|token)/.test((row.url || '').toLowerCase()))

  if (!sensitive.length) return '## DATA EXPOSURE / PII FOOTPRINT\n- No sensitive endpoints highlighted yet.'

  const lines = sensitive.slice(0, 6).map(row => `- ${row.url || row.title} -> status ${row.statusCode ?? '-'}`)
  if (sensitive.length > 6) lines.push(`- ... +${sensitive.length - 6} additional sensitive-looking endpoints`)

  return `## DATA EXPOSURE / PII FOOTPRINT\n${lines.join('\n')}`
}

function buildInfrastructureSection(snapshots: SectionSnapshots): string {
  const dnsRows = getRenderableRows(snapshots.dns)
  const reputationRows = getRenderableRows(snapshots.reputation)
  const sslRows = getRenderableRows(snapshots.ssl)
  const lines: string[] = []

  if (dnsRows.length) {
    lines.push(`- DNS hygiene findings (${dnsRows.length}) e.g., ${formatTopList(dnsRows.map(r => r.title || r.url || r.host || 'record'), 3)}`)
  }
  if (reputationRows.length) {
    lines.push(`- Reputation feeds (${reputationRows.length}) sample: ${formatTopList(reputationRows.map(r => r.title || r.url).filter(Boolean), 3)}`)
  }
  if (sslRows.length) {
    const invalid = sslRows.filter(r => r.sslInfo && !r.sslInfo.isValid)
    if (invalid.length) lines.push(`- ${invalid.length} hosts with invalid or broken certificates`)
  }

  if (!lines.length) lines.push('- No infrastructure telemetry captured yet.')

  return `## INFRASTRUCTURE SIGNALS\n${lines.join('\n')}`
}

function buildDownloadableMarkdown(report: string, meta: { target: string, generatedAt: string }): string {
  const generatedDate = new Date(meta.generatedAt)
  const header = [
    '# SecRon Recon Report',
    `- Target: ${meta.target}`,
    `- Generated: ${generatedDate.toLocaleString()} (${meta.generatedAt})`,
    `- Sections: ${countSections(report)}`
  ].join('\n')

  const highlightLines = report
    .split('\n')
    .filter(line => line.trim().startsWith('[i]'))
    .slice(0, 8)
    .map(line => `- ${line.replace(/^\[i\]\s*/, '💡 ')}`)

  const highlightBlock = highlightLines.length
    ? `\n## Highlights\n${highlightLines.join('\n')}\n`
    : ''

  return `${header}${highlightBlock}\n${report}`
}

function countSections(report: string): number {
  return report.split('\n').filter(line => line.startsWith('## ')).length
}

function getRenderableRows(response: ReconResponse | null): ReconRow[] {
  if (!response || !Array.isArray(response.results)) return []
  return response.results.filter(row => !(row as any).isSubdomainHeader)
}

function gatherHostsFromSection(response: ReconResponse | null): string[] {
  if (response?.mergedSubdomains?.length) {
    return dedupeArray([...response.mergedSubdomains])
  }
  const rows = getRenderableRows(response)
  const hosts = rows
    .map(row => resolveHost(row))
    .filter((host): host is string => !!host)
  return dedupeArray(hosts)
}

function resolveHost(row: ReconRow): string {
  if (row.host) return row.host
  const parsed = safeParseUrl(row.url)
  return parsed?.hostname || ''
}

function safeParseUrl(value?: string): URL | null {
  if (!value) return null
  try {
    if (!/^https?:\/\//i.test(value)) {
      return new URL(`https://${value}`)
    }
    return new URL(value)
  } catch {
    return null
  }
}

function extractQueryParams(parsed: URL | null): string[] {
  if (!parsed) return []
  return Array.from(parsed.searchParams.keys())
}

function formatTopList(values: string[], limit = 5): string {
  if (!values.length) return 'none'
  const sliced = values.slice(0, limit)
  const extra = values.length - sliced.length
  return `${sliced.join(', ')}${extra > 0 ? ` +${extra} more` : ''}`
}

function dedupeArray<T>(values: T[]): T[] {
  return Array.from(new Set(values))
}

function extractCvesFromText(text?: string | null): string[] {
  if (!text) return []
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi)
  if (!matches) return []
  return matches.map(m => m.toUpperCase())
}

function deriveRowCves(row: ReconRow): string[] {
  const direct = Array.isArray(row.cves)
    ? row.cves.filter((c): c is string => !!c).map(c => c.toUpperCase())
    : []
  const techCves = (row.technologies || []).flatMap(extractCvesFromText)
  const titleCves = extractCvesFromText(row.title)
  const hostCves = extractCvesFromText(row.host)
  const urlCves = extractCvesFromText(row.url)
  return dedupeArray([...direct, ...techCves, ...titleCves, ...hostCves, ...urlCves])
}

function extractPortFromRow(row: ReconRow): number | null {
  const sources = [row.title, row.url]
  for (const source of sources) {
    if (!source) continue
    const match = source.match(/:(\d{2,5})/)
    if (match) return Number(match[1])
  }
  return null
}

function collectHeaderHints(host: string, headerRows: ReconRow[]): string {
  if (!host || !headerRows.length) return 'not observed'
  const relevant = headerRows.filter(row => {
    const rowHost = resolveHost(row)
    return rowHost && (rowHost === host || rowHost.endsWith(`.${host}`) || host.endsWith(`.${rowHost}`))
  })
  if (!relevant.length) return 'not observed'
  const tags = dedupeArray(relevant.flatMap(row => row.technologies || []))
  if (tags.length) return tags.slice(0, 3).join(', ')
  const titles = relevant.map(row => row.title).filter(Boolean)
  return titles.slice(0, 2).join(', ') || 'headers captured'
}

function summarizeHeaderSignals(rows: ReconRow[]) {
  if (!rows.length) {
    return {
      cookieFlag: 'NOT CHECKED',
      browserHeaders: 'NOT CHECKED',
      waf: 'NOT CHECKED',
      csp: 'NOT CHECKED',
      clientEncoding: 'NOT CHECKED',
      serverEncoding: 'NOT CHECKED',
    }
  }

  const text = rows
    .flatMap(row => [
      row.title || '',
      row.url || '',
      row.host || '',
      ...(row.technologies || []),
    ])
    .join(' ')
    .toLowerCase()

  const contains = (keywords: string | string[]) => {
    const list = Array.isArray(keywords) ? keywords : [keywords]
    return list.some(keyword => text.includes(keyword))
  }

  return {
    cookieFlag: contains(['secure', 'httponly', 'samesite']) ? 'LIKELY' : 'NOT OBSERVED',
    browserHeaders: contains(['strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy']) ? 'PRESENT' : 'NOT OBSERVED',
    waf: contains(['cloudflare', 'akamai', 'imperva', 'fastly', 'aws waf', 'f5']) ? 'LIKELY' : 'NOT OBSERVED',
    csp: contains(['content-security-policy', 'csp']) ? 'PRESENT' : 'NOT OBSERVED',
    clientEncoding: contains(['react', 'vue', 'client encode', 'escape']) ? 'PARTIAL' : 'UNKNOWN',
    serverEncoding: contains(['sanitize', 'validation', 'encoded server', 'orm']) ? 'PARTIAL' : 'UNKNOWN',
  }
}

export default App