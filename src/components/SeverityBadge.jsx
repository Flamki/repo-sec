import React from 'react'

const SEVERITY_CONFIG = {
  CRITICAL: {
    color: '#ff3355',
    bg: 'rgba(255,51,85,0.12)',
    border: 'rgba(255,51,85,0.35)',
    glow: '0 0 12px rgba(255,51,85,0.4)',
    label: 'CRITICAL',
  },
  HIGH: {
    color: '#ff6b35',
    bg: 'rgba(255,107,53,0.12)',
    border: 'rgba(255,107,53,0.35)',
    glow: '0 0 12px rgba(255,107,53,0.4)',
    label: 'HIGH',
  },
  MEDIUM: {
    color: '#ffaa00',
    bg: 'rgba(255,170,0,0.12)',
    border: 'rgba(255,170,0,0.35)',
    glow: '0 0 12px rgba(255,170,0,0.4)',
    label: 'MEDIUM',
  },
  LOW: {
    color: '#4db8ff',
    bg: 'rgba(77,184,255,0.12)',
    border: 'rgba(77,184,255,0.35)',
    glow: '0 0 12px rgba(77,184,255,0.4)',
    label: 'LOW',
  },
  CLEAN: {
    color: '#00ff88',
    bg: 'rgba(0,255,136,0.12)',
    border: 'rgba(0,255,136,0.35)',
    glow: '0 0 12px rgba(0,255,136,0.4)',
    label: 'CLEAN',
  },
}

export default function SeverityBadge({ severity, size = 'sm', pulse = false }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG['LOW']

  const sizes = {
    xs: { fontSize: '9px', padding: '2px 7px', dotSize: '5px', gap: '4px' },
    sm: { fontSize: '10px', padding: '3px 10px', dotSize: '6px', gap: '5px' },
    md: { fontSize: '12px', padding: '5px 14px', dotSize: '8px', gap: '6px' },
    lg: { fontSize: '14px', padding: '7px 18px', dotSize: '10px', gap: '7px' },
    xl: { fontSize: '18px', padding: '10px 24px', dotSize: '12px', gap: '8px' },
  }

  const s = sizes[size] || sizes['sm']

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: s.gap,
        padding: s.padding,
        borderRadius: '999px',
        border: `1px solid ${cfg.border}`,
        background: cfg.bg,
        color: cfg.color,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: s.fontSize,
        fontWeight: 700,
        letterSpacing: '0.08em',
        boxShadow: cfg.glow,
        whiteSpace: 'nowrap',
      }}
    >
      <span
        style={{
          width: s.dotSize,
          height: s.dotSize,
          borderRadius: '50%',
          background: cfg.color,
          flexShrink: 0,
          boxShadow: `0 0 6px ${cfg.color}`,
          animation: pulse ? 'badgePulse 1.5s ease-in-out infinite' : 'none',
        }}
      />
      {cfg.label}
    </span>
  )
}

export { SEVERITY_CONFIG }
