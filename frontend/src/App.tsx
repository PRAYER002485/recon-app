import { useEffect, useMemo, useState } from 'react'
import './App.css'

type ReconRow = {
  url: string
  host: string
  statusCode: number | null
  title: string
  technologies: string[]
}

type ReconResponse = {
  target: string
  count: number
  results: ReconRow[]
}

function App() {
  const API_BASE = (import.meta as any).env?.VITE_API_BASE || ''
  const [stage, setStage] = useState<'home' | 'workspace'>('home')
  const [activeSection, setActiveSection] = useState<'subdomains' | 'ports' | 'js' | 'nmap'>('subdomains')
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ReconResponse | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
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
  function getSectionCacheKey(section: 'subdomains' | 'ports' | 'js' | 'nmap', t: string) {
    return `recon-cache:${section}:${t}:${mode}`
  }
  function loadSectionCache(section: 'subdomains' | 'ports' | 'js' | 'nmap', t: string): ReconResponse | null {
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
  function saveSectionCache(section: 'subdomains' | 'ports' | 'js' | 'nmap', t: string, payload: ReconResponse) {
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

  async function runJsScan() {
    if (!target.trim()) return
    setLoading(true)
    setError(null)
    setData(null)
    try {
      const resp = await fetch(`${API_BASE}/api/js-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      })
      if (!resp.ok) throw new Error(await resp.text())
      const json = await resp.json()
      const rows = (json.js || []).map((u: string) => ({ url: u, host: new URL(u).hostname, statusCode: null, title: 'JS', technologies: [] as string[] }))
      const shaped: ReconResponse = { target: json.target, count: rows.length, results: rows }
      setData(shaped)
      saveSectionCache('js', target.trim(), shaped)
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
      const shaped: ReconResponse = { target: json.target, count: json.count, results: (json.results || []) }
      setData(shaped)
      saveSectionCache('nmap', target.trim(), shaped)
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
    const section = (params.get('section') as 'subdomains' | 'ports' | 'js' | 'nmap' | null) || null

    if (!t) {
      try { t = sessionStorage.getItem('lastTarget') || '' } catch {}
    }

    if (pathname.startsWith('/subdomains') || pathname.startsWith('/ports') || pathname.startsWith('/js') || pathname.startsWith('/nmap') || t) {
      if (t) setTarget(t)
      setStage('workspace')
      const sec = section || (pathname.startsWith('/ports') ? 'ports' : pathname.startsWith('/js') ? 'js' : pathname.startsWith('/nmap') ? 'nmap' : 'subdomains')
      setActiveSection(sec)

      if (t) {
        // Show cached immediately if present
        const cached = loadSectionCache(sec, t)
        if (cached) setData(cached)

        // Only run if no cache exists
        if (!cached) {
          if (sec === 'ports') runPorts()
          else if (sec === 'js') runJsScan()
          else if (sec === 'nmap') runNmap()
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
          <h1>Recon Dashboard</h1>
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
            <div className="brand">Recon</div>
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
                className={`navItem ${activeSection === 'js' ? 'active' : ''}`}
                onClick={() => {
                  setActiveSection('js')
                  setError(null)
                  const t = target.trim()
                  const params = new URLSearchParams()
                  if (t) params.set('target', t)
                  params.set('section', 'js')
                  window.history.pushState(null, '', `/js?${params.toString()}`)
                  if (t) {
                    const cached = loadSectionCache('js', t)
                    if (cached) setData(cached)
                    else runJsScan()
                  }
                }}
              >
                JavaScript Scan
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
                  <button onClick={runPorts} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run ports'}
                  </button>
                )}
                {activeSection === 'js' && (
                  <button onClick={runJsScan} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run JS scan'}
                  </button>
                )}
                {activeSection === 'nmap' && (
                  <button onClick={runNmap} disabled={loading}>
                    {loading ? 'Scanning...' : 'Run nmap'}
                  </button>
                )}
              </div>
            </header>

            {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}

            {(activeSection === 'subdomains' || activeSection === 'ports' || activeSection === 'js' || activeSection === 'nmap') && (
              <section className="results">
                {data && (
                  <div className="summary">
                    <span><strong>Target:</strong> {data.target}</span>
                    <span><strong>Entries:</strong> {data.count}</span>
                    <button className="drawerBtn" onClick={() => setDrawerOpen(v => !v)}>
                      {drawerOpen ? 'Hide' : 'Show'} Subdomains
                    </button>
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
                    <table>
                      <thead>
                        <tr>
                          <th>URL</th>
                          <th>Status</th>
                          <th>Title</th>
                          <th>Technologies</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.results.map((r, i) => (
                          <tr key={r.url + i}>
                            <td><a href={r.url} target="_blank" rel="noreferrer">{r.url}</a></td>
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