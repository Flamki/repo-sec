import React, { useState, useEffect, useCallback } from 'react'
import { Shield, ExternalLink } from 'lucide-react'
import ScanForm from './components/ScanForm.jsx'
import ScanResults from './components/ScanResults.jsx'
import RecentScans from './components/RecentScans.jsx'
import ScanProgress from './components/ScanProgress.jsx'
import Leaderboard from './components/Leaderboard.jsx'
import './styles.css'

function useApiHealth() {
  const [alive, setAlive] = useState(null)

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch('/health', { signal: AbortSignal.timeout(3000) })
        setAlive(res.ok)
      } catch {
        setAlive(false)
      }
    }
    check()
    const iv = setInterval(check, 30000)
    return () => clearInterval(iv)
  }, [])

  return alive
}

export default function App() {
  const [scanData, setScanData] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [activeScanId, setActiveScanId] = useState(null)
  const [leaderboardRefreshToken, setLeaderboardRefreshToken] = useState(0)
  const apiAlive = useApiHealth()

  const handleScanComplete = useCallback((data) => {
    setScanData(data)
    setActiveScanId(data.scanId)
    setLeaderboardRefreshToken((n) => n + 1)
    // Scroll to results
    setTimeout(() => {
      document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 100)
  }, [])

  const handleScanStart = useCallback(() => {
    setScanData(null)
    setActiveScanId(null)
    setScanning(true)
  }, [])

  const handleScanEnd = useCallback(() => {
    setScanning(false)
  }, [])

  // Wrap onScanComplete to also clear scanning state
  const wrappedComplete = useCallback((data) => {
    setScanning(false)
    handleScanComplete(data)
  }, [handleScanComplete])

  const wrappedError = useCallback(() => {
    setScanning(false)
  }, [])

  const handleSelectRecentScan = useCallback((scan) => {
    setScanData(scan)
    setActiveScanId(scan.scanId)
    setTimeout(() => {
      document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, 100)
  }, [])

  return (
    <div className="app">
      {/* Scanlines texture overlay */}
      <div className="scanlines" aria-hidden="true" />

      {/* Grid bg */}
      <div className="grid-bg" aria-hidden="true" />

      {/* Header */}
      <header className="site-header">
        <div className="header-inner">
          <div className="header-logo">
            <div className="logo-shield">
              <Shield size={22} color="#00ff88" strokeWidth={2} />
              <div className="shield-glow" />
            </div>
            <div className="logo-text">
              <span className="logo-repo">repo</span><span className="logo-sec">-sec</span>
            </div>
            <div className="logo-badge">v1.0</div>
          </div>

          <div className="header-subtitle">
            AI-Discoverable Security Scanner · MCP Enabled
          </div>

          <div className="header-right">
            <a href="/docs" className="header-link" target="_blank" rel="noopener noreferrer">
              Swagger Docs
            </a>
            <a href="/skill.json" className="header-link" target="_blank" rel="noopener noreferrer">
              skill.json
            </a>
            <div className={`api-status ${apiAlive === true ? 'live' : apiAlive === false ? 'down' : 'checking'}`}>
              <span className="status-dot" />
              <span className="status-text">
                {apiAlive === true ? 'API Live' : apiAlive === false ? 'API Down' : 'Checking...'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="main-content">
        {/* Hero / Scan form */}
        <ScanForm
          onScanComplete={wrappedComplete}
          onScanStart={handleScanStart}
          onScanError={wrappedError}
        />

        {/* Terminal-style scan progress */}
        <ScanProgress active={scanning} />

        {/* Results */}
        {scanData && (
          <div id="results">
            <ScanResults data={scanData} />
          </div>
        )}

        {/* Recent scans */}
        <RecentScans
          onSelectScan={handleSelectRecentScan}
          activeScanId={activeScanId}
        />

        <Leaderboard refreshToken={leaderboardRefreshToken} />
      </main>

      {/* Footer */}
      <footer className="site-footer">
        <div className="footer-inner">
          <div className="footer-left">
            <div className="footer-brand">
              <Shield size={14} color="rgba(0,255,136,0.5)" />
              <span className="footer-logo-text">
                <span style={{ color: '#c8c8c8' }}>repo</span><span style={{ color: '#00ff88' }}>-sec</span>
              </span>
            </div>
            <span className="footer-tagline">AI-powered GitHub security scanning for the modern stack</span>
          </div>

          <div className="footer-center">
            <div className="footer-spec-badge">
              <span className="spec-dot" />
              OpenAPI 3.1 · MCP-Discoverable · /openapi.json
            </div>
          </div>

          <div className="footer-right">
            <a href="/docs" className="footer-link" target="_blank" rel="noopener noreferrer">
              <ExternalLink size={10} />
              /docs
            </a>
            <a href="/skill.json" className="footer-link" target="_blank" rel="noopener noreferrer">
              <ExternalLink size={10} />
              /skill.json
            </a>
            <a href="/openapi.json" className="footer-link" target="_blank" rel="noopener noreferrer">
              <ExternalLink size={10} />
              /openapi.json
            </a>
          </div>
        </div>
      </footer>

      {/* CreateOS Badge */}
      <style>{`
        #createos-badge {
          position: fixed;
          bottom: 12px;
          right: 12px;
          z-index: 9999;
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 6px 10px;
          background: rgba(255,255,255,0.92);
          backdrop-filter: blur(8px);
          border: 1px solid rgba(0,0,0,0.08);
          border-radius: 999px;
          box-shadow: 0 1px 4px rgba(0,0,0,0.10);
          font-size: 11px;
          font-weight: 500;
          color: #374151;
          text-decoration: none;
          font-family: system-ui, sans-serif;
        }
        #createos-badge:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
        #createos-badge img { width: 14px; height: 14px; }
      `}</style>
      <a id="createos-badge" href="https://createos.sh/app" target="_blank" rel="noopener noreferrer">
        <img src="https://nodeops.network/SymbolBlack.svg" alt="" />
        Built with CreateOS
      </a>
    </div>
  )
}
