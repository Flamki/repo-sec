import React, { useState, useEffect, useRef } from 'react'

/**
 * Terminal-style scan progress that simulates pipeline stages.
 * Shows realistic step-by-step progress while the actual scan runs.
 */

const STAGES = [
  { id: 'connect', text: 'Connecting to GitHub API', duration: 800 },
  { id: 'tree', text: 'Fetching repository file tree', duration: 1200 },
  { id: 'download', text: 'Downloading scannable files', duration: 3000 },
  { id: 'secrets', text: 'Running secrets detection · 30+ patterns', duration: 2500 },
  { id: 'osv', text: 'Querying OSV.dev vulnerability database', duration: 4000 },
  { id: 'misconfig', text: 'Checking misconfigurations', duration: 1500 },
  { id: 'analyze', text: 'Analyzing results · generating fix suggestions', duration: 2000 },
]

export default function ScanProgress({ active }) {
  const [completedStages, setCompletedStages] = useState([])
  const [currentStage, setCurrentStage] = useState(0)
  const [dots, setDots] = useState('')
  const containerRef = useRef(null)

  // Advance through stages
  useEffect(() => {
    if (!active) {
      setCompletedStages([])
      setCurrentStage(0)
      return
    }

    let timeout
    const advance = (stage) => {
      if (stage >= STAGES.length) return
      setCurrentStage(stage)
      timeout = setTimeout(() => {
        setCompletedStages(prev => [...prev, STAGES[stage].id])
        advance(stage + 1)
      }, STAGES[stage].duration)
    }
    advance(0)

    return () => clearTimeout(timeout)
  }, [active])

  // Animate dots
  useEffect(() => {
    if (!active) return
    const iv = setInterval(() => {
      setDots(prev => prev.length >= 3 ? '' : prev + '.')
    }, 400)
    return () => clearInterval(iv)
  }, [active])

  // Auto-scroll
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [completedStages, currentStage])

  if (!active) return null

  return (
    <div className="scan-terminal">
      <div className="scan-terminal-header">
        <div className="terminal-dots">
          <span className="tdot red" />
          <span className="tdot yellow" />
          <span className="tdot green" />
        </div>
        <span className="terminal-title">repo-sec · scan pipeline</span>
      </div>
      <div className="scan-terminal-body" ref={containerRef}>
        <div className="terminal-line system">
          <span className="terminal-prefix">$</span>
          <span>repo-sec scan --deep --all-checks</span>
        </div>

        {STAGES.map((stage, i) => {
          const isCompleted = completedStages.includes(stage.id)
          const isCurrent = currentStage === i && !isCompleted

          if (i > currentStage && !isCompleted) return null

          return (
            <div
              key={stage.id}
              className={`terminal-line ${isCompleted ? 'completed' : ''} ${isCurrent ? 'current' : ''}`}
            >
              <span className="terminal-status">
                {isCompleted ? (
                  <span className="status-check">✓</span>
                ) : isCurrent ? (
                  <span className="status-spinner" />
                ) : null}
              </span>
              <span className="terminal-text">
                {stage.text}
                {isCurrent && <span className="terminal-dots-anim">{dots}</span>}
              </span>
              {isCompleted && (
                <span className="terminal-done">done</span>
              )}
            </div>
          )
        })}

        {completedStages.length === STAGES.length && (
          <div className="terminal-line system final">
            <span className="terminal-prefix">&gt;</span>
            <span>Scan complete. Waiting for results...</span>
          </div>
        )}
      </div>
    </div>
  )
}
