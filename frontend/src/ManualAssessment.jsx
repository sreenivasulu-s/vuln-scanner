
import { useEffect, useState } from 'react'

const API_BASE = 'http://127.0.0.1:8000'

export default function ManualAssessment({ scan }) {
  const [state, setState] = useState(null)
  const [catalog, setCatalog] = useState([])
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')

  async function loadManualState() {
    if (!scan) return

    setLoading(true)

    try {
      const response = await fetch(
        `${API_BASE}/manual/scan/${scan.scan_id}`,
      )

      if (!response.ok) {
        throw new Error('Failed to load manual assessment state')
      }

      const data = await response.json()
      setState(data)
    } catch (err) {
      setError(err.message || 'Manual assessment state failed')
    } finally {
      setLoading(false)
    }
  }

  async function loadCatalog() {
    try {
      const response = await fetch(
        `${API_BASE}/manual/catalog`,
      )

      if (!response.ok) {
        throw new Error('Failed to load assessment catalog')
      }

      const data = await response.json()
      setCatalog(data.categories || [])
    } catch (err) {
      setError(err.message || 'Assessment catalog failed')
    }
  }

  async function syncBurp() {
    if (!scan) return

    setSyncing(true)
    setError('')

    try {
      const response = await fetch(
        `${API_BASE}/manual/scan/${scan.scan_id}/burp-sync`,
        { method: 'POST' },
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.detail || 'Burp synchronization failed',
        )
      }

      setState((current) => ({
        ...(current || {}),
        burp_mcp: data.burp_mcp || current?.burp_mcp,
        last_sync: data,
      }))

      await loadManualState()
    } catch (err) {
      setError(err.message || 'Burp synchronization failed')
    } finally {
      setSyncing(false)
    }
  }

  useEffect(() => {
    loadCatalog()
  }, [])

  useEffect(() => {
    if (!scan || scan.status !== 'completed') return

    loadManualState()
  }, [scan?.scan_id, scan?.status])

  if (!scan) return null

  const burp = state?.burp_mcp
  const alerts = state?.alerts || []
  const coverage = state?.coverage || []

  const observed = coverage.filter(
    (item) => item.state === 'potential',
  ).length

  const manualCount = coverage.filter(
    (item) => item.manual_validation,
  ).length

  return (
    <section className="card manual-assessment">
      <div className="section-header">
        <div>
          <h2>Manual Security Assessment</h2>
          <p className="target">
            Automated scan hand-off to Burp Suite + MCP-assisted
            analyst validation.
          </p>
        </div>

        <span
          className={`manual-badge ${
            scan.status === 'completed'
              ? 'action'
              : 'pending'
          }`}
        >
          {scan.status === 'completed'
            ? 'ACTION REQUIRED'
            : 'WAITING'}
        </span>
      </div>

      {loading && (
        <p className="target">
          Checking manual-assessment readiness...
        </p>
      )}

      {alerts.length > 0 && (
        <div className="manual-alert">
          <strong>🚨 Manual testing alert</strong>

          {alerts.map((alert, index) => (
            <p key={`${alert.type}-${index}`}>
              {alert.message}
            </p>
          ))}
        </div>
      )}

      <div className="manual-grid">
        <div className="manual-stat">
          <span>Assessment categories</span>
          <strong>{catalog.length || 30}</strong>
        </div>

        <div className="manual-stat">
          <span>Observed by automation</span>
          <strong>{observed}</strong>
        </div>

        <div className="manual-stat">
          <span>Manual validation</span>
          <strong>{manualCount}</strong>
        </div>

        <div className="manual-stat">
          <span>Burp MCP</span>
          <strong>
            {burp?.reachable
              ? 'CONNECTED'
              : 'NOT CONNECTED'}
          </strong>
        </div>
      </div>

      <div className="manual-actions">
        <button
          type="button"
          className="history-refresh"
          onClick={loadManualState}
          disabled={loading}
        >
          {loading ? 'Checking...' : 'Check MCP Status'}
        </button>

        <button
          type="button"
          className="history-refresh"
          onClick={syncBurp}
          disabled={syncing || !burp?.reachable}
        >
          {syncing
            ? 'Syncing Burp...'
            : 'Sync Burp Findings'}
        </button>
      </div>

      <div className="manual-handoff">
        <strong>ChatGPT / MCP hand-off</strong>
        <p>
          Use the authorized MCP assessment tools to review
          Burp evidence and manually validate applicable
          vulnerability categories. Raw shell access is not
          exposed to the AI.
        </p>

        <code>
          MCP server: http://127.0.0.1:8765
        </code>
      </div>

      <div className="manual-catalog">
        <h3>30-category assessment coverage</h3>

        <div className="manual-category-list">
          {coverage.length > 0
            ? coverage.map((item) => (
                <div
                  className="manual-category"
                  key={item.key}
                >
                  <span>
                    {item.name}
                  </span>

                  <span
                    className={
                      item.state === 'potential'
                        ? 'category-observed'
                        : 'category-unchecked'
                    }
                  >
                    {item.state === 'potential'
                      ? 'OBSERVED'
                      : 'NOT OBSERVED'}
                  </span>
                </div>
              ))
            : catalog.map((item) => (
                <div
                  className="manual-category"
                  key={item.key}
                >
                  <span>{item.name}</span>

                  <span
                    className={
                      item.manual_validation
                        ? 'category-unchecked'
                        : 'category-automated'
                    }
                  >
                    {item.manual_validation
                      ? 'MANUAL'
                      : 'AUTOMATED'}
                  </span>
                </div>
              ))}
        </div>
      </div>

      {error && (
        <p className="error">
          {error}
        </p>
      )}
    </section>
  )
}
