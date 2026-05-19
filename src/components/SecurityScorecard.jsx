import React from 'react'
import RadarChart from './RadarChart.jsx'

/**
 * Security Scorecard — OSSF-inspired repository health visualization.
 * Shows an overall grade (A-F), radar chart, and individual check scores.
 */

const WEIGHT_COLORS = {
  critical: '#ff3355',
  high: '#ff6b35',
  medium: '#ffaa00',
  low: '#4db8ff',
}

const GRADE_COLORS = {
  A: '#00ff88',
  B: '#4db8ff',
  C: '#ffaa00',
  D: '#ff6b35',
  F: '#ff3355',
}

export default function SecurityScorecard({ scorecard }) {
  if (!scorecard) return null

  const gradeColor = GRADE_COLORS[scorecard.grade] || '#5f6368'

  return (
    <div className="scorecard">
      <div className="scorecard-header">
        <div className="scorecard-title-row">
          <span className="scorecard-icon">🛡️</span>
          <span className="scorecard-title">Security Scorecard</span>
          <span className="scorecard-subtitle">OSSF-inspired</span>
        </div>

        <div className="scorecard-grade-wrap">
          <div className="scorecard-grade" style={{ borderColor: gradeColor, color: gradeColor }}>
            {scorecard.grade}
          </div>
          <div className="scorecard-overall">
            <span className="scorecard-score" style={{ color: gradeColor }}>{scorecard.overallScore}</span>
            <span className="scorecard-max">/10</span>
          </div>
        </div>
      </div>

      {/* Radar + Checks layout */}
      <div className="scorecard-body">
        <div className="scorecard-radar">
          <RadarChart scorecard={scorecard} />
        </div>

        <div className="scorecard-checks">
          {scorecard.checks.map((check, i) => {
            const pct = (check.score / check.maxScore) * 100
            const color = check.score >= 8 ? '#00ff88'
              : check.score >= 5 ? '#ffaa00'
              : check.score > 0 ? '#ff6b35'
              : '#ff3355'

            return (
              <div key={i} className="scorecard-check">
                <div className="check-header">
                  <span className="check-name">{check.name}</span>
                  <div className="check-meta">
                    <span
                      className="check-weight"
                      style={{ color: WEIGHT_COLORS[check.weight] || '#5f6368' }}
                    >
                      {check.weight}
                    </span>
                    <span className="check-score" style={{ color }}>
                      {check.score}/{check.maxScore}
                    </span>
                  </div>
                </div>
                <div className="check-bar-track">
                  <div
                    className="check-bar-fill"
                    style={{
                      width: `${pct}%`,
                      background: `linear-gradient(90deg, ${color}88, ${color})`,
                      boxShadow: `0 0 8px ${color}40`,
                    }}
                  />
                </div>
                <div className="check-reason">{check.reason}</div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
