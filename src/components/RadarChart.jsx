import React, { useEffect, useState } from 'react'

/**
 * SVG Radar Chart — decagonal (10-point) chart for security scorecard.
 * Enterprise-grade visualization used by top security dashboards.
 */

const SIZE = 240
const CENTER = SIZE / 2
const LEVELS = 5  // Number of concentric rings
const GRADE_COLORS = { A: '#00ff88', B: '#4db8ff', C: '#ffaa00', D: '#ff6b35', F: '#ff3355' }

export default function RadarChart({ scorecard }) {
  const [animPct, setAnimPct] = useState(0)

  useEffect(() => {
    let frame
    const start = performance.now()
    const duration = 1200
    const animate = (now) => {
      const p = Math.min((now - start) / duration, 1)
      setAnimPct(p * p * (3 - 2 * p)) // smoothstep easing
      if (p < 1) frame = requestAnimationFrame(animate)
    }
    frame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(frame)
  }, [scorecard])

  if (!scorecard || !scorecard.checks) return null

  const checks = scorecard.checks
  const n = checks.length
  const angleStep = (2 * Math.PI) / n
  const maxRadius = CENTER - 30

  // Get point on radar for a given index and value (0-10)
  const getPoint = (index, value) => {
    const angle = angleStep * index - Math.PI / 2
    const r = (value / 10) * maxRadius * animPct
    return {
      x: CENTER + r * Math.cos(angle),
      y: CENTER + r * Math.sin(angle),
    }
  }

  // Build data polygon
  const dataPoints = checks.map((check, i) => getPoint(i, check.score))
  const dataPath = dataPoints.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ') + ' Z'

  // Build concentric level rings
  const levelRings = []
  for (let level = 1; level <= LEVELS; level++) {
    const r = (level / LEVELS) * maxRadius
    const points = []
    for (let i = 0; i < n; i++) {
      const angle = angleStep * i - Math.PI / 2
      points.push(`${CENTER + r * Math.cos(angle)},${CENTER + r * Math.sin(angle)}`)
    }
    levelRings.push(points.join(' '))
  }

  // Build axes
  const axes = checks.map((_, i) => {
    const angle = angleStep * i - Math.PI / 2
    return {
      x2: CENTER + maxRadius * Math.cos(angle),
      y2: CENTER + maxRadius * Math.sin(angle),
    }
  })

  // Labels
  const labels = checks.map((check, i) => {
    const angle = angleStep * i - Math.PI / 2
    const labelR = maxRadius + 18
    const x = CENTER + labelR * Math.cos(angle)
    const y = CENTER + labelR * Math.sin(angle)
    // Short labels
    const shortName = check.name.replace('Vulnerability-Free', 'Vuln-Free')
      .replace('Pinned-Dependencies', 'Pinned-Deps')
      .replace('Secure-Config', 'Sec-Config')
    return { x, y, name: shortName, score: check.score }
  })

  const gradeColor = GRADE_COLORS[scorecard.grade] || '#5f6368'

  return (
    <div className="radar-chart-wrap">
      <svg
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        className="radar-chart-svg"
        width={SIZE}
        height={SIZE}
      >
        <defs>
          <radialGradient id="radarGlow">
            <stop offset="0%" stopColor={gradeColor} stopOpacity="0.3" />
            <stop offset="100%" stopColor={gradeColor} stopOpacity="0.03" />
          </radialGradient>
        </defs>

        {/* Concentric level rings */}
        {levelRings.map((points, i) => (
          <polygon
            key={i}
            points={points}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="0.5"
          />
        ))}

        {/* Axes */}
        {axes.map((axis, i) => (
          <line
            key={i}
            x1={CENTER} y1={CENTER}
            x2={axis.x2} y2={axis.y2}
            stroke="rgba(255,255,255,0.08)"
            strokeWidth="0.5"
          />
        ))}

        {/* Data polygon fill */}
        <path
          d={dataPath}
          fill="url(#radarGlow)"
          stroke={gradeColor}
          strokeWidth="1.5"
          strokeLinejoin="round"
          opacity="0.9"
        />

        {/* Data points */}
        {dataPoints.map((p, i) => (
          <circle
            key={i}
            cx={p.x} cy={p.y}
            r="3"
            fill={checks[i].score >= 8 ? '#00ff88' : checks[i].score >= 5 ? '#ffaa00' : '#ff3355'}
            stroke="#0d1117"
            strokeWidth="1"
          />
        ))}

        {/* Labels */}
        {labels.map((label, i) => (
          <text
            key={i}
            x={label.x}
            y={label.y}
            textAnchor="middle"
            dominantBaseline="middle"
            fill={label.score >= 8 ? 'rgba(232,234,237,0.6)' : label.score >= 5 ? 'rgba(255,170,0,0.8)' : 'rgba(255,51,85,0.8)'}
            fontSize="6"
            fontFamily="'JetBrains Mono', monospace"
            fontWeight="500"
          >
            {label.name}
          </text>
        ))}
      </svg>
    </div>
  )
}
