import React, { useState, useCallback } from 'react'
import { Zap } from 'lucide-react'

export default function ScanForm({ onScanComplete, onScanStart }) {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState('')
  const [inputFocused, setInputFocused] = useState(false)

  const validate = (val) => {
    if (!val.trim()) return 'Please enter a GitHub repository URL'
    if (!val.startsWith('https://github.com/')) return 'URL must start with https://github.com/'
    const parts = val.replace('https://github.com/', '').split('/')
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      return 'URL must be in format https://github.com/owner/repo'
    }
    return ''
  }

  const handleScan = useCallback(async () => {
    const validationError = validate(url)
    if (validationError) {
      setError(validationError)
      return
    }
    setError('')
    setScanning(true)
    onScanStart && onScanStart()

    try {
      const res = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: url.trim() }),
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.message || body.error || `Server error: ${res.status}`)
      }

      const json = await res.json()
      if (!json.success) {
        throw new Error(json.message || json.error || 'Scan failed')
      }

      onScanComplete && onScanComplete(json.data)
    } catch (err) {
      setError(err.message || 'Scan failed. Please try again.')
    } finally {
      setScanning(false)
    }
  }, [url, onScanComplete, onScanStart])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !scanning) handleScan()
  }

  const handleChange = (e) => {
    setUrl(e.target.value)
    if (error) setError('')
  }

  return (
    <section className="scan-form-section">
      <div className="scan-form-container">
        <div className="scan-headline">
          <div className="scan-headline-eyebrow">
            <span className="eyebrow-dot" />
            <span>SECURITY ANALYSIS ENGINE</span>
          </div>
          <h1 className="scan-title">
            Scan any GitHub repository<br />
            <span style={{ color: '#00ff88' }}>for security vulnerabilities</span>
          </h1>
          <p className="scan-subtitle">
            Powered by AI · Detects secrets, CVEs, and misconfigurations · MCP-accessible
          </p>
        </div>

        <div className="scan-input-row">
          <div
            className={`scan-input-wrapper ${inputFocused ? 'focused' : ''} ${error ? 'has-error' : ''} ${scanning ? 'scanning' : ''}`}
          >
            {/* Scanner sweep animation */}
            {scanning && <div className="sweep-line" />}

            <div className="input-prefix">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
              </svg>
            </div>

            <input
              type="text"
              className="scan-input"
              value={url}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
              onFocus={() => setInputFocused(true)}
              onBlur={() => setInputFocused(false)}
              placeholder="https://github.com/owner/repo"
              disabled={scanning}
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          <button
            className={`scan-button ${scanning ? 'scanning' : ''}`}
            onClick={handleScan}
            disabled={scanning}
          >
            {scanning ? (
              <span className="scan-button-inner">
                <span className="scan-spinner" />
                <span>SCANNING...</span>
              </span>
            ) : (
              <span className="scan-button-inner">
                <Zap size={15} fill="currentColor" />
                <span>SCAN REPOSITORY</span>
              </span>
            )}
          </button>
        </div>

        {error && (
          <div className="scan-error">
            <span style={{ color: '#ff3355', marginRight: '6px' }}>⚠</span>
            {error}
          </div>
        )}

        {scanning && (
          <div className="scan-progress-text">
            <span className="progress-dot" />
            Initializing deep scan · Fetching repository tree · Analyzing dependencies...
          </div>
        )}

        <div className="scan-tags">
          {['Secrets Detection', 'CVE Matching', 'Misconfig Analysis', 'AI-Powered', 'MCP Enabled'].map((tag) => (
            <span key={tag} className="scan-tag">{tag}</span>
          ))}
        </div>
      </div>
    </section>
  )
}
