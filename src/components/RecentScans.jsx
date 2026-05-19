import React, { useEffect, useState, useCallback } from 'react'
import { Clock, RefreshCw } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

function timeAgo(isoString) {
  if (!isoString) return '—'
  const diff = Date.now() - new Date(isoString).getTime()
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function SkeletonRow() {
  return (
    <div className="recent-scan-row skeleton">
      <div className="skeleton-dot" />
      <div className="skeleton-lines">
        <div className="skeleton-line long" />
        <div className="skeleton-line short" />
      </div>
      <div className="skeleton-badge" />
    </div>
  )
}

export default function RecentScans({ onSelectScan, activeScanId }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchScans = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError('')
    try {
      const res = await fetch('/scans')
      if (!res.ok) throw new Error(`Failed to load scans (${res.status})`)
      const json = await res.json()
      if (!json.success) throw new Error(json.message || 'Failed to load scans')
      const data = Array.isArray(json.data) ? json.data : []
      // Show last 10
      setScans(data.slice(0, 10))
      setLastRefresh(new Date())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    fetchScans(false)
  }, [fetchScans])

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(() => fetchScans(true), 30000)
    return () => clearInterval(interval)
  }, [fetchScans])

  const handleRefresh = () => {
    if (!refreshing) fetchScans(true)
  }

  return (
    <section className="recent-scans-section">
      <div className="recent-scans-header">
        <div className="recent-scans-title">
          <Clock size={14} color="rgba(0,255,136,0.6)" />
          <span>Recent Scans</span>
          {scans.length > 0 && (
            <span className="recent-count">{scans.length}</span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {lastRefresh && (
            <span className="recent-refresh-time">
              Updated {timeAgo(lastRefresh.toISOString())}
            </span>
          )}
          <button
            className={`refresh-btn ${refreshing ? 'spinning' : ''}`}
            onClick={handleRefresh}
            title="Refresh scans"
            disabled={refreshing}
          >
            <RefreshCw size={12} />
          </button>
        </div>
      </div>

      <div className="recent-scans-list">
        {loading ? (
          Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
        ) : error ? (
          <div className="recent-error">
            <span style={{ color: '#ff3355' }}>⚠</span>
            <span>{error}</span>
            <button className="recent-retry-btn" onClick={() => fetchScans(false)}>Retry</button>
          </div>
        ) : scans.length === 0 ? (
          <div className="recent-empty">
            <div className="recent-empty-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="rgba(0,255,136,0.2)" strokeWidth="1.5">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
            </div>
            <span>No scans yet. Run your first scan above.</span>
          </div>
        ) : (
          scans.map((scan, i) => (
            <button
              key={scan.scanId || i}
              className={`recent-scan-row ${activeScanId === scan.scanId ? 'active' : ''}`}
              onClick={() => onSelectScan && onSelectScan(scan)}
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <div className="recent-scan-left">
                <SeverityBadge severity={scan.severity || 'CLEAN'} size="xs" />
                <div className="recent-scan-info">
                  <span className="recent-repo-name">
                    {scan.repoName || scan.repoUrl?.replace('https://github.com/', '') || 'unknown'}
                  </span>
                  <span className="recent-meta">
                    <span>{timeAgo(scan.scannedAt)}</span>
                    <span className="recent-meta-dot">·</span>
                    <span style={{ color: scan.findingsCount > 0 ? '#ff8855' : '#00ff88' }}>
                      {scan.findingsCount || 0} finding{scan.findingsCount !== 1 ? 's' : ''}
                    </span>
                  </span>
                </div>
              </div>

              <div className="recent-scan-right">
                {scan.filesScanned != null && (
                  <span className="recent-files">{scan.filesScanned} files</span>
                )}
                {activeScanId === scan.scanId && (
                  <span className="recent-active-dot" />
                )}
              </div>
            </button>
          ))
        )}
      </div>
    </section>
  )
}
