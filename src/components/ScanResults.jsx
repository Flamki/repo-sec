import React, { useState, useEffect, useRef } from 'react'
import { CheckCircle, AlertTriangle, FileCode, Clock } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'
import FindingCard from './FindingCard.jsx'

function useCountUp(target, duration = 800) {
  const [count, setCount] = useState(0)
  const raf = useRef(null)

  useEffect(() => {
    if (target === 0) { setCount(0); return }
    const start = performance.now()
    const animate = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setCount(Math.round(eased * target))
      if (progress < 1) raf.current = requestAnimationFrame(animate)
    }
    raf.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(raf.current)
  }, [target, duration])

  return count
}

const TABS = [
  { key: 'SECRET', label: 'Secrets', icon: '🔑' },
  { key: 'VULNERABILITY', label: 'Vulnerabilities', icon: '⚠' },
  { key: 'MISCONFIGURATION', label: 'Misconfigs', icon: '⚙' },
]

export default function ScanResults({ data }) {
  const [activeTab, setActiveTab] = useState('SECRET')
  const filesCount = useCountUp(data.filesScanned || 0)
  const findingsCount = useCountUp(data.findingsCount || 0)
  const durationSec = ((data.durationMs || 0) / 1000).toFixed(2)

  const findingsByType = (type) =>
    (data.findings || []).filter((f) => f.type === type)

  const getFixForFinding = (findingId) =>
    (data.fixSuggestions || []).find((s) => s.findingId === findingId)

  const isClean = data.severity === 'CLEAN' || (data.findings || []).length === 0

  const repoName = data.repoName || data.repoUrl?.replace('https://github.com/', '') || 'unknown/repo'

  // Auto-select first tab that has findings
  useEffect(() => {
    const order = ['SECRET', 'VULNERABILITY', 'MISCONFIGURATION']
    for (const type of order) {
      if (findingsByType(type).length > 0) {
        setActiveTab(type)
        break
      }
    }
  }, [data])

  return (
    <section className="results-section">
      {/* Summary bar */}
      <div className="results-header">
        <div className="results-repo-line">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(0,255,136,0.6)" strokeWidth="2">
            <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
          </svg>
          <span className="results-repo-name">{repoName}</span>
        </div>

        <div className="results-stats-row">
          <SeverityBadge severity={data.severity || 'CLEAN'} size="lg" pulse={!isClean} />

          <div className="results-stats">
            <div className="stat-item">
              <FileCode size={13} color="#5f6368" />
              <span className="stat-value">{filesCount}</span>
              <span className="stat-label">files scanned</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <AlertTriangle size={13} color="#5f6368" />
              <span className="stat-value" style={{ color: findingsCount > 0 ? '#ff3355' : '#00ff88' }}>
                {findingsCount}
              </span>
              <span className="stat-label">findings</span>
            </div>
            <div className="stat-divider" />
            <div className="stat-item">
              <Clock size={13} color="#5f6368" />
              <span className="stat-value">{durationSec}s</span>
              <span className="stat-label">scan time</span>
            </div>
          </div>
        </div>

        {data.scannedAt && (
          <div className="results-timestamp">
            Scanned at {new Date(data.scannedAt).toLocaleString()}
          </div>
        )}
      </div>

      {/* CLEAN state */}
      {isClean ? (
        <div className="clean-state">
          <div className="clean-icon-wrap">
            <CheckCircle size={56} color="#00ff88" />
            <div className="clean-ring" />
          </div>
          <h2 className="clean-title">No Issues Found</h2>
          <p className="clean-desc">
            This repository passed all security checks. No secrets, vulnerabilities, or misconfigurations detected.
          </p>
          <div className="clean-checks">
            {['Secrets scan', 'CVE matching', 'Misconfiguration audit', 'Dependency analysis'].map((c) => (
              <div key={c} className="clean-check-item">
                <CheckCircle size={12} color="#00ff88" />
                <span>{c}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          {/* Tabs */}
          <div className="results-tabs">
            {TABS.map((tab) => {
              const count = findingsByType(tab.key).length
              return (
                <button
                  key={tab.key}
                  className={`results-tab ${activeTab === tab.key ? 'active' : ''} ${count === 0 ? 'empty' : ''}`}
                  onClick={() => setActiveTab(tab.key)}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                  {count > 0 && (
                    <span className="tab-count">{count}</span>
                  )}
                </button>
              )
            })}
          </div>

          {/* Findings list */}
          <div className="findings-list">
            {findingsByType(activeTab).length === 0 ? (
              <div className="no-findings-tab">
                <CheckCircle size={20} color="rgba(0,255,136,0.4)" />
                <span>No {TABS.find(t => t.key === activeTab)?.label.toLowerCase()} detected</span>
              </div>
            ) : (
              findingsByType(activeTab).map((finding, i) => (
                <FindingCard
                  key={finding.id || i}
                  finding={finding}
                  fixSuggestion={getFixForFinding(finding.id)}
                  index={i}
                />
              ))
            )}
          </div>

          {/* Fix suggestions summary */}
          {data.fixSuggestions && data.fixSuggestions.length > 0 && (
            <div className="fix-suggestions-panel">
              <div className="fix-suggestions-header">
                <div className="fix-suggestions-title">
                  <span className="fix-icon">⚡</span>
                  Remediation Plan
                </div>
                <span className="fix-suggestions-count">{data.fixSuggestions.length} actions</span>
              </div>
              <div className="fix-suggestions-list">
                {data.fixSuggestions.map((fix, i) => {
                  const finding = (data.findings || []).find(f => f.id === fix.findingId)
                  return (
                    <div key={i} className="fix-suggestion-row">
                      <div className="fix-number">{String(i + 1).padStart(2, '0')}</div>
                      <div className="fix-content">
                        <div className="fix-action-line">
                          <span className={`fix-priority fix-priority-${fix.priority}`}>{fix.priority}</span>
                          <span className="fix-action">{fix.action}</span>
                        </div>
                        {finding && (
                          <div className="fix-finding-ref">↳ {finding.title}</div>
                        )}
                        <div className="fix-detail">{fix.detail}</div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
