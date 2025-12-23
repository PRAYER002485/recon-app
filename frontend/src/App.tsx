import { useEffect, useMemo, useState } from 'react'
import './App.css'

type ReconRow = {
  url: string
  host: string
  statusCode: number | null
  title: string
  technologies: string[]
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

type ReconResponse = {
  target: string
  count: number
  results: ReconRow[]
}

const SECTION_KEYS = ['subdomains', 'ports', 'urls', 'nmap', 'ssl', 'breach', 'headers', 'dns', 'reputation', 'buckets'] as const
type SectionKey = typeof SECTION_KEYS[number]
type SectionSnapshots = Record<SectionKey, ReconResponse | null>

function createEmptySnapshots(): SectionSnapshots {
  return SECTION_KEYS.reduce((acc, key) => {
    acc[key] = null
    return acc
  }, {} as SectionSnapshots)
}

// Helper function to check if a string is an IP address
function isIPAddress(str: string): boolean {
  // IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4Regex.test(str)) {
    const parts = str.split('.')
    return parts.every(part => {
      const num = parseInt(part, 10)
      return num >= 0 && num <= 255
    })
  }
  // IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/
  return ipv6Regex.test(str)
}

function App() {
  const API_BASE = (import.meta as any).env?.VITE_API_BASE || ''
  const [stage, setStage] = useState<'home' | 'workspace'>('home')
  const [activeSection, setActiveSection] = useState<SectionKey>('subdomains')
  const [target, setTarget] = useState('')
  const [breachEmail, setBreachEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ReconResponse | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [expandedCves, setExpandedCves] = useState<Set<string>>(new Set())
  const [sectionSnapshots, setSectionSnapshots] = useState<SectionSnapshots>(() => createEmptySnapshots())
  const [reportOpen, setReportOpen] = useState(false)
  const [reportText, setReportText] = useState('')
  const [reportMeta, setReportMeta] = useState<{ target: string, generatedAt: string } | null>(null)
  const [reportGenerating, setReportGenerating] = useState(false)
  const mode: 'fast' | 'full' = 'fast'

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

  function toggleCveExpansion(rowIndex: number) {
    const key = `row-${rowIndex}`
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

  const subdomains = useMemo(() => {
    if (!data) return [] as string[]
    const set = new Set<string>()
    for (const r of data.results) {
      const host = r.host || (r.url ? new URL(r.url).hostname : '')
      // Filter out IP addresses and empty strings
      if (host && !isIPAddress(host)) {
        set.add(host)
      }
    }
    return Array.from(set).sort()
  }, [data])

  const hasReportMaterial = useMemo(() => SECTION_KEYS.some(key => !!sectionSnapshots[key]), [sectionSnapshots])

  useEffect(() => {
    if (!data) return
    setSectionSnapshots(prev => ({ ...prev, [activeSection]: data }))
  }, [data, activeSection])

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

  async function runUrlsScan() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/urls-scan`, {
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
          isSubdomainHeader: r.isSubdomainHeader || false,
          parentSubdomain: r.parentSubdomain || null
        }))
      }
      setData(shaped)
      saveSectionCache('urls', target.trim(), shaped)
    } catch (e: any) {
      setError(e.message || String(e))
    } finally {
      setLoading(false)
    }
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
    const section = (params.get('section') as 'subdomains' | 'ports' | 'urls' | 'nmap' | 'ssl' | 'breach' | null) || null

    if (!t) {
      try { t = sessionStorage.getItem('lastTarget') || '' } catch {}
    }

    if (pathname.startsWith('/subdomains') || pathname.startsWith('/ports') || pathname.startsWith('/urls') || pathname.startsWith('/nmap') || pathname.startsWith('/ssl') || pathname.startsWith('/breach') || pathname.startsWith('/headers') || pathname.startsWith('/dns') || pathname.startsWith('/reputation') || pathname.startsWith('/buckets') || t) {
      if (t) setTarget(t)
      setStage('workspace')
      const sec = section || (pathname.startsWith('/ports') ? 'ports' : pathname.startsWith('/urls') ? 'urls' : pathname.startsWith('/nmap') ? 'nmap' : pathname.startsWith('/ssl') ? 'ssl' : pathname.startsWith('/breach') ? 'breach' : pathname.startsWith('/headers') ? 'headers' : pathname.startsWith('/dns') ? 'dns' : pathname.startsWith('/reputation') ? 'reputation' : pathname.startsWith('/buckets') ? 'buckets' : 'subdomains')
      setActiveSection(sec)

      if (t) {
        // Show cached immediately if present
        const cached = loadSectionCache(sec, t)
        if (cached) setData(cached)

        // Only run if no cache exists
        if (!cached) {
          if (sec === 'ports') runPorts()
          else if (sec === 'urls') runUrlsScan()
          else if (sec === 'nmap') runNmap()
          else if (sec === 'ssl') runSSLCheck()
          else if (sec === 'headers') runHeadersCheck()
          else if (sec === 'dns') runDNSHygiene()
          else if (sec === 'reputation') runReputation()
          else if (sec === 'buckets') runBuckets()
          else if (sec === 'breach') {/* wait for manual run with email */}
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
          <h1>SecRon Dashboard</h1>
          <p>Enter a wildcard, domain, or IP to enumerate subdomains and tech.</p>
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
                  <button onClick={runUrlsScan} disabled={loading}>
                    {loading ? 'Fetching URLs...' : 'Run URLs scan'}
                  </button>
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
                {activeSection === 'breach' && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <input
                      className="homeInput"
                      style={{ maxWidth: 300 }}
                      value={breachEmail}
                      onChange={e => setBreachEmail(e.target.value)}
                      placeholder="[email protected]"
                      onKeyDown={(e) => { if (e.key === 'Enter') runBreachCheck() }}
                    />
                    <button onClick={runBreachCheck} disabled={loading || !breachEmail.trim()}>
                      {loading ? 'Checking...' : 'Check breaches'}
                    </button>
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

          
            {(activeSection === 'subdomains' || activeSection === 'ports' || activeSection === 'urls' || activeSection === 'nmap' || activeSection === 'ssl' || activeSection === 'breach' || activeSection === 'buckets' || activeSection === 'dns' || activeSection === 'reputation' || activeSection === 'headers') && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>{activeSection === 'breach' ? 'Email' : 'Target'}:</strong> {data.target}</span>
                    <span><strong>Entries:</strong> {data.count}</span>
                    {activeSection === 'urls' && (data as any).totalSubdomains && (
                      <span><strong>Subdomains:</strong> {(data as any).subdomainsWithHistory}/{(data as any).totalSubdomains} with history</span>
                    )}
                    <button className="drawerBtn" onClick={() => setDrawerOpen(v => !v)}>
                      {drawerOpen ? 'Hide' : 'Show'} Subdomains
                    </button>
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

                <div className={`drawer ${drawerOpen ? 'open' : ''}`}>
                  <h3>Subdomains</h3>
                  <ul>
                    {subdomains.map(sd => (
                      <li key={sd}>{sd}</li>
                    ))}
                  </ul>
                </div>

                {data ? (
                  <div className="tableWrap">
                    <table className={`resultsTable ${activeSection}-table`}>
                      <thead>
                        <tr>
                          <th>{activeSection === 'breach' ? 'Record' : 'URL'}</th>
                          <th>Status</th>
                          <th>Title</th>
                          <th>Technologies</th>
                          {activeSection === 'nmap' && (<th>Found CVEs</th>)}
                          {activeSection === 'ssl' && (<th>SSL Details</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {data.results.map((r, i) => {
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
                            <td>{r.statusCode ?? '-'}</td>
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
                                    {(expandedCves.has(`row-${i}`) ? r.vulnDetails : r.vulnDetails.slice(0, 5)).map((v, j) => (
                                      <div key={v.cve + j} className="vuln-item">
                                        <span className="cve-tag">{v.cve}</span>
                                        <span className="score">({v.score})</span>
                                        <div className="description">{v.description}</div>
                                      </div>
                                    ))}
                                    {r.vulnDetails.length > 5 && (
                                      <div 
                                        className="more-vulns" 
                                        onClick={() => toggleCveExpansion(i)}
                                        style={{ cursor: 'pointer' }}
                                      >
                                        {expandedCves.has(`row-${i}`) 
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
                ) : (
                  !loading && <div className="placeholder">Click "Run again" to populate results.</div>
                )}
              </section>
            )}
          </main>
        </div>
      )}

      <footer>
        <span>Techificial.ai</span>
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