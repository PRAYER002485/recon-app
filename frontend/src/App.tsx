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

function App() {
  const API_BASE = (import.meta as any).env?.VITE_API_BASE || ''
  const [stage, setStage] = useState<'home' | 'workspace'>('home')
  const [activeSection, setActiveSection] = useState<'subdomains' | 'ports' | 'urls' | 'nmap' | 'ssl' | 'breach' | 'headers' | 'dns' | 'reputation' | 'buckets'>('subdomains')
  const [target, setTarget] = useState('')
  const [breachEmail, setBreachEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ReconResponse | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [expandedCves, setExpandedCves] = useState<Set<string>>(new Set())
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
  function getSectionCacheKey(section: 'subdomains' | 'ports' | 'urls' | 'nmap' | 'ssl' | 'breach' | 'headers' | 'dns' | 'reputation' | 'buckets', t: string) {
    return `recon-cache:${section}:${t}:${mode}`
  }
  function loadSectionCache(section: 'subdomains' | 'ports' | 'urls' | 'nmap' | 'ssl' | 'breach' | 'headers' | 'dns' | 'reputation' | 'buckets', t: string): ReconResponse | null {
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
  function saveSectionCache(section: 'subdomains' | 'ports' | 'urls' | 'nmap' | 'ssl' | 'breach' | 'headers' | 'dns' | 'reputation' | 'buckets', t: string, payload: ReconResponse) {
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
      if (host) set.add(host)
    }
    return Array.from(set).sort()
  }, [data])

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
              </div>
            </header>

            {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

          
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
                        {data.results.map((r, i) => (
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
                                ) : r.cves && r.cves.length > 0 ? (
                                  <div className="tags">
                                    {r.cves.map((c, j) => (
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
                        ))}
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

export default App