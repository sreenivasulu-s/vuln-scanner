import { useEffect, useState } from 'react'
import './App.css'

const API_BASE = 'http://127.0.0.1:8000'
const STORAGE_KEY = 'vuln-scanner-scan-id'

function App() {
  const [url, setUrl] = useState('')
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [severity, setSeverity] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)

  async function loadHistory() {
    setHistoryLoading(true)

    try {
      const response = await fetch(`${API_BASE}/scans`)

      if (!response.ok) {
        throw new Error('Failed to load scan history')
      }

      const data = await response.json()
      setHistory(data)
    } catch (err) {
      setError(err.message || 'Failed to load scan history')
    } finally {
      setHistoryLoading(false)
    }
  }

  async function selectHistoricalScan(scanId) {
    setError('')
    setSeverity('')

    try {
      const data = await loadScan(scanId)
      localStorage.setItem(STORAGE_KEY, scanId)

      if (data.status === 'queued' || data.status === 'running') {
        let currentScan = data

        while (
          currentScan.status === 'queued' ||
          currentScan.status === 'running'
        ) {
          await new Promise((resolve) => setTimeout(resolve, 1000))
          currentScan = await loadScan(scanId)
        }
      }

      await loadHistory()
    } catch (err) {
      setError(err.message || 'Failed to load historical scan')
    }
  }

  async function loadScan(scanId) {
    const response = await fetch(`${API_BASE}/scan/${scanId}`)

    if (!response.ok) {
      localStorage.removeItem(STORAGE_KEY)
      throw new Error('Failed to load saved scan')
    }

    const data = await response.json()

    setScan(data)
    setFindings(data.findings || [])

    return data
  }

  useEffect(() => {
    loadHistory()

    const savedScanId = localStorage.getItem(STORAGE_KEY)

    if (!savedScanId) return

    let cancelled = false
    let timerId

    async function pollScan() {
      try {
        const response = await fetch(
          `${API_BASE}/scan/${savedScanId}`
        )

        if (!response.ok) {
          localStorage.removeItem(STORAGE_KEY)
          throw new Error('Failed to restore scan')
        }

        const data = await response.json()

        if (cancelled) return

        setScan(data)
        setFindings(data.findings || [])

        if (data.status === 'queued' || data.status === 'running') {
          timerId = setTimeout(pollScan, 1000)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to restore scan')
        }
      }
    }

    pollScan()

    return () => {
      cancelled = true
      clearTimeout(timerId)
    }
  }, [])

  async function startScan(event) {
    event.preventDefault()

    setLoading(true)
    setError('')
    setScan(null)
    setFindings([])
    setSeverity('')

    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))

        throw new Error(
          data.detail?.[0]?.msg || 'Scan request failed'
        )
      }

      const data = await response.json()

      localStorage.setItem(STORAGE_KEY, data.scan_id)

      setScan(data)
      setFindings(data.findings || [])

      await loadHistory()

      let currentScan = data

      while (
        currentScan.status === 'queued' ||
        currentScan.status === 'running'
      ) {
        await new Promise((resolve) => setTimeout(resolve, 1000))

        currentScan = await loadScan(data.scan_id)
      }
    } catch (err) {
      setError(err.message || 'Network request failed')
    } finally {
      setLoading(false)
    }
  }

  async function filterFindings(value) {
    setSeverity(value)

    if (!scan) return

    const endpoint = value
      ? `${API_BASE}/scan/${scan.scan_id}/findings?severity=${encodeURIComponent(value)}`
      : `${API_BASE}/scan/${scan.scan_id}/findings`

    try {
      const response = await fetch(endpoint)

      if (!response.ok) {
        throw new Error('Failed to fetch findings')
      }

      const data = await response.json()

      setFindings(data.findings || [])
    } catch (err) {
      setError(err.message || 'Failed to load findings')
    }
  }

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">AUTHORIZED LAB</p>

          <h1>Web Security Scanner</h1>

          <p className="subtitle">
            Submit a target and review scanner findings.
          </p>
        </div>

        <span className="status-badge">
          API Connected
        </span>
      </header>

      <section className="card">
        <h2>Start a scan</h2>

        <form onSubmit={startScan} className="scan-form">
          <input
            type="url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="http://127.0.0.1:8000"
            required
          />

          <button type="submit" disabled={loading}>
            {loading ? 'Scanning...' : 'Start Scan'}
          </button>
        </form>

        {error && (
          <p className="error">
            {error}
          </p>
        )}
      </section>


      <section className="card">
        <div className="section-header">
          <div>
            <h2>Scan History</h2>
            <p className="target">
              Previous scans from this scanner session.
            </p>
          </div>

          <button
            type="button"
            className="history-refresh"
            onClick={loadHistory}
            disabled={historyLoading}
          >
            {historyLoading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {history.length === 0 ? (
          <p className="empty">
            {historyLoading
              ? 'Loading scan history...'
              : 'No previous scans yet.'}
          </p>
        ) : (
          <div className="history-list">
            {history.map((item) => (
              <button
                type="button"
                className={`history-item ${
                  scan?.scan_id === item.scan_id ? 'selected' : ''
                }`}
                key={item.scan_id}
                onClick={() => selectHistoricalScan(item.scan_id)}
              >
                <span className="history-target">
                  {item.target}
                </span>

                <span className="history-details">
                  <span className={`scan-status ${item.status}`}>
                    {item.status}
                  </span>

                  <span className="history-count">
                    {item.findings_count}{' '}
                    {item.findings_count === 1 ? 'finding' : 'findings'}
                  </span>
                </span>
              </button>
            ))}
          </div>
        )}
      </section>

      {scan && (
        <section className="card">
          <div className="section-header">
            <div>
              <h2>Scan Status</h2>

              <p className="target">
                {scan.target}
              </p>
            </div>

            <span className={`scan-status ${scan.status}`}>
              {scan.status}
            </span>
          </div>

          <div className="scan-meta">
            <div>
              <strong>Scan ID</strong>
              <span>{scan.scan_id}</span>
            </div>

            <div>
              <strong>Status</strong>
              <span>{scan.status}</span>
            </div>
          </div>

          <div className="findings-header">
            <h2>Findings</h2>

            <select
              value={severity}
              onChange={(event) =>
                filterFindings(event.target.value)
              }
            >
              <option value="">All severities</option>
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          {findings.length === 0 ? (
            <p className="empty">
              No findings returned yet.
            </p>
          ) : (
            <div className="findings">
              {findings.map((finding, index) => (
                <article
                  className="finding"
                  key={`${finding.title}-${index}`}
                >
                  <div className="finding-header">
                    <h3>{finding.title}</h3>

                    <span
                      className={`severity ${finding.severity}`}
                    >
                      {finding.severity}
                    </span>
                  </div>

                  <p>
                    {finding.description}
                  </p>

                  <p>
                    <strong>Evidence:</strong>{' '}
                    {finding.evidence}
                  </p>

                  <p>
                    <strong>Tool:</strong>{' '}
                    {finding.tool}
                  </p>
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </main>
  )
}

export default App
