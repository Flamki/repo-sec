import React, { useState, useEffect, useRef } from 'react'

/**
 * Animated circular threat score gauge.
 * Score 0-100 with color gradient from green (safe) to red (critical).
 */

const SEVERITY_SCORE_MAP = {
  CRITICAL: { min: 80, color: '#ff3355', label: 'CRITICAL RISK' },
  HIGH:     { min: 60, color: '#ff6b35', label: 'HIGH RISK' },
  MEDIUM:   { min: 35, color: '#ffaa00', label: 'MEDIUM RISK' },
  LOW:      { min: 15, color: '#4db8ff', label: 'LOW RISK' },
  CLEAN:    { min: 0,  color: '#00ff88', label: 'SECURE' },
}

function calculateThreatScore(findings) {
  if (!findings || findings.length === 0) return 0

  // Count by severity
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++
  }

  // Determine score tier based on highest severity present
  // The tier sets the CEILING — many MEDIUMs can't exceed HIGH range
  let base = 0, ceiling = 0
  if (counts.CRITICAL > 0)     { base = 75; ceiling = 100 }
  else if (counts.HIGH > 0)    { base = 50; ceiling = 82 }
  else if (counts.MEDIUM > 0)  { base = 25; ceiling = 58 }
  else if (counts.LOW > 0)     { base = 5;  ceiling = 28 }

  // Scale within the tier using log(count) for diminishing returns
  const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW
  const scaleFactor = Math.min(Math.log2(total + 1) / 5, 1) // 0→1 over ~32 findings
  const score = base + (ceiling - base) * scaleFactor

  return Math.round(Math.min(score, 100))
}

function getScoreColor(score) {
  if (score >= 80) return '#ff3355'
  if (score >= 60) return '#ff6b35'
  if (score >= 35) return '#ffaa00'
  if (score >= 15) return '#4db8ff'
  return '#00ff88'
}

function getScoreLabel(score) {
  if (score >= 80) return 'CRITICAL RISK'
  if (score >= 60) return 'HIGH RISK'
  if (score >= 35) return 'MEDIUM RISK'
  if (score >= 15) return 'LOW RISK'
  return 'SECURE'
}

function useAnimatedValue(target, duration = 1200) {
  const [value, setValue] = useState(0)
  const raf = useRef(null)

  useEffect(() => {
    const start = performance.now()
    const animate = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 4) // ease-out quart
      setValue(eased * target)
      if (progress < 1) raf.current = requestAnimationFrame(animate)
    }
    raf.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(raf.current)
  }, [target, duration])

  return value
}

export default function ThreatGauge({ findings, severity }) {
  const score = calculateThreatScore(findings)
  const animatedScore = useAnimatedValue(score, 1400)
  const color = getScoreColor(score)
  const label = getScoreLabel(score)

  // SVG arc math
  const size = 160
  const strokeWidth = 10
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const progress = animatedScore / 100
  const dashOffset = circumference * (1 - progress)

  // Glow filter ID
  const filterId = `gauge-glow-${score}`

  return (
    <div className="threat-gauge">
      <div className="threat-gauge-ring">
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          style={{ transform: 'rotate(-90deg)' }}
        >
          <defs>
            <filter id={filterId}>
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="gauge-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={color} stopOpacity="1" />
              <stop offset="100%" stopColor={color} stopOpacity="0.6" />
            </linearGradient>
          </defs>

          {/* Background track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth={strokeWidth}
          />

          {/* Tick marks */}
          {Array.from({ length: 40 }).map((_, i) => {
            const angle = (i / 40) * 360
            const rad = (angle * Math.PI) / 180
            const isMajor = i % 10 === 0
            const innerR = radius - (isMajor ? 8 : 4)
            const outerR = radius + 2
            return (
              <line
                key={i}
                x1={size / 2 + innerR * Math.cos(rad)}
                y1={size / 2 + innerR * Math.sin(rad)}
                x2={size / 2 + outerR * Math.cos(rad)}
                y2={size / 2 + outerR * Math.sin(rad)}
                stroke={i / 40 <= progress ? color : 'rgba(255,255,255,0.08)'}
                strokeWidth={isMajor ? 1.5 : 0.5}
                style={{ transition: 'stroke 0.3s' }}
              />
            )
          })}

          {/* Progress arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={`url(#gauge-gradient)`}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            filter={`url(#${filterId})`}
            style={{ transition: 'stroke-dashoffset 0.1s linear' }}
          />
        </svg>

        {/* Center content */}
        <div className="threat-gauge-center">
          <span className="threat-gauge-score" style={{ color }}>
            {Math.round(animatedScore)}
          </span>
          <span className="threat-gauge-max">/100</span>
        </div>
      </div>

      <div className="threat-gauge-label" style={{ color }}>
        <span className="threat-gauge-dot" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
        {label}
      </div>

      {/* Mini breakdown */}
      <div className="threat-gauge-breakdown">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
          const count = (findings || []).filter(f => f.severity === sev).length
          if (count === 0) return null
          const cfg = SEVERITY_SCORE_MAP[sev]
          return (
            <div key={sev} className="breakdown-item">
              <span className="breakdown-dot" style={{ background: cfg.color }} />
              <span className="breakdown-count" style={{ color: cfg.color }}>{count}</span>
              <span className="breakdown-label">{sev.toLowerCase()}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export { calculateThreatScore }
