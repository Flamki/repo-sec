import React, { useCallback, useEffect, useState } from 'react'
import { Trophy, RefreshCw } from 'lucide-react'

function scoreLabel(score) {
  if (typeof score !== 'number') return 'N/A'
  return score.toFixed(1)
}

export default function Leaderboard({ refreshToken = 0 }) {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [refreshing, setRefreshing] = useState(false)

  const fetchBoard = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true)
    else setLoading(true)
    setError('')

    try {
      const res = await fetch('/leaderboard')
      if (!res.ok) throw new Error(`Failed to load leaderboard (${res.status})`)
      const json = await res.json()
      if (!json.success) throw new Error(json.message || 'Failed to load leaderboard')
      const data = Array.isArray(json.data) ? json.data : []
      setRows(data)
    } catch (err) {
      setError(err.message || 'Failed to load leaderboard')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchBoard(false)
  }, [fetchBoard])

  useEffect(() => {
    if (refreshToken > 0) fetchBoard(true)
  }, [refreshToken, fetchBoard])

  useEffect(() => {
    const iv = setInterval(() => fetchBoard(true), 30000)
    return () => clearInterval(iv)
  }, [fetchBoard])

  return (
    <section className="leaderboard-section">
      <div className="leaderboard-header">
        <div className="leaderboard-title">
          <Trophy size={14} color="rgba(255,170,0,0.85)" />
          <span>Leaderboard</span>
          <span className="leaderboard-count">{rows.length}</span>
        </div>

        <button
          className={`refresh-btn ${refreshing ? 'spinning' : ''}`}
          onClick={() => !refreshing && fetchBoard(true)}
          title="Refresh leaderboard"
          disabled={refreshing}
        >
          <RefreshCw size={12} />
        </button>
      </div>

      {loading ? (
        <div className="leaderboard-empty">Loading leaderboard...</div>
      ) : error ? (
        <div className="leaderboard-empty">{error}</div>
      ) : rows.length === 0 ? (
        <div className="leaderboard-empty">No scans yet.</div>
      ) : (
        <div className="leaderboard-table">
          <div className="leaderboard-row leaderboard-row-head">
            <span>Website</span>
            <span>Score</span>
          </div>
          {rows.map((row, i) => (
            <div key={row.repoName} className="leaderboard-row">
              <span className="leaderboard-repo">
                <span className="leaderboard-rank">{String(i + 1).padStart(2, '0')}</span>
                <span>{row.repoName}</span>
              </span>
              <span className="leaderboard-score">{scoreLabel(row.score)}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
