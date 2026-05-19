import React, { useState } from 'react'
import { FileCode, ChevronDown, ExternalLink, Eye } from 'lucide-react'
import SeverityBadge, { SEVERITY_CONFIG } from './SeverityBadge.jsx'

const TYPE_ICONS = {
  SECRET: '🔑',
  VULNERABILITY: '⚠',
  MISCONFIGURATION: '⚙',
}

export default function FindingCard({ finding, fixSuggestion, index }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG['LOW']

  return (
    <div
      className="finding-card"
      style={{
        '--card-color': cfg.color,
        '--card-border': cfg.border,
        '--card-bg': cfg.bg,
        animationDelay: `${index * 80}ms`,
      }}
    >
      <div className="finding-card-inner">
        {/* Left severity bar */}
        <div
          style={{
            width: '3px',
            borderRadius: '2px',
            background: cfg.color,
            boxShadow: `0 0 8px ${cfg.color}`,
            flexShrink: 0,
            alignSelf: 'stretch',
          }}
        />

        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Header row */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '14px', marginTop: '1px' }}>{TYPE_ICONS[finding.type] || '•'}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
                <span style={{
                  fontFamily: "'DM Sans', sans-serif",
                  fontWeight: 600,
                  fontSize: '14px',
                  color: '#e8eaed',
                }}>
                  {finding.title}
                </span>
                <SeverityBadge severity={finding.severity} size="xs" />
                {finding.cve && (
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '3px',
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '10px',
                      color: '#4db8ff',
                      textDecoration: 'none',
                      border: '1px solid rgba(77,184,255,0.3)',
                      borderRadius: '4px',
                      padding: '1px 6px',
                    }}
                  >
                    {finding.cve}
                    <ExternalLink size={9} />
                  </a>
                )}
              </div>

              {/* File path */}
              {finding.file && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '6px' }}>
                  <FileCode size={11} color="rgba(0,255,136,0.6)" />
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '11px',
                    color: 'rgba(0,255,136,0.75)',
                  }}>
                    {finding.file}{finding.line ? `:${finding.line}` : ''}
                  </span>
                </div>
              )}

              {/* Description */}
              <p style={{
                fontFamily: "'DM Sans', sans-serif",
                fontSize: '13px',
                color: '#9aa0a6',
                margin: '0 0 8px 0',
                lineHeight: '1.5',
              }}>
                {finding.description}
              </p>

              {/* Evidence block */}
              {finding.evidence && (
                <div style={{
                  background: 'rgba(0,0,0,0.5)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  marginBottom: '8px',
                  position: 'relative',
                  overflow: 'hidden',
                }}>
                  <div style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    height: '1px',
                    background: `linear-gradient(90deg, transparent, ${cfg.color}40, transparent)`,
                  }} />
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    marginBottom: '4px',
                  }}>
                    <Eye size={10} color="#5f6368" />
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '9px',
                      color: '#5f6368',
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                    }}>Evidence</span>
                  </div>
                  <code style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '11px',
                    color: '#c5c9d0',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    display: 'block',
                  }}>
                    {finding.evidence}
                  </code>
                </div>
              )}

              {/* Fix suggestion toggle */}
              {fixSuggestion && (
                <div>
                  <button
                    onClick={() => setExpanded(!expanded)}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      background: 'none',
                      border: 'none',
                      color: cfg.color,
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '11px',
                      cursor: 'pointer',
                      padding: '3px 0',
                      opacity: 0.85,
                    }}
                  >
                    <ChevronDown
                      size={12}
                      style={{
                        transition: 'transform 0.2s',
                        transform: expanded ? 'rotate(180deg)' : 'none',
                      }}
                    />
                    {expanded ? 'Hide fix suggestion' : 'Show fix suggestion'}
                  </button>

                  {expanded && (
                    <div
                      style={{
                        marginTop: '8px',
                        padding: '10px 12px',
                        background: 'rgba(0,255,136,0.04)',
                        border: '1px solid rgba(0,255,136,0.12)',
                        borderRadius: '6px',
                        animation: 'fadeIn 0.2s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                        <span style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '9px',
                          color: '#00ff88',
                          letterSpacing: '0.1em',
                          textTransform: 'uppercase',
                          background: 'rgba(0,255,136,0.12)',
                          border: '1px solid rgba(0,255,136,0.2)',
                          borderRadius: '3px',
                          padding: '1px 6px',
                        }}>
                          {fixSuggestion.priority} PRIORITY
                        </span>
                      </div>
                      <p style={{
                        fontFamily: "'DM Sans', sans-serif",
                        fontSize: '13px',
                        fontWeight: 600,
                        color: '#c8f7dc',
                        margin: '0 0 4px 0',
                      }}>
                        {fixSuggestion.action}
                      </p>
                      <p style={{
                        fontFamily: "'DM Sans', sans-serif",
                        fontSize: '12px',
                        color: '#8fa89a',
                        margin: '0 0 8px 0',
                        lineHeight: '1.5',
                      }}>
                        {fixSuggestion.detail}
                      </p>
                      {fixSuggestion.resources && fixSuggestion.resources.length > 0 && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          {fixSuggestion.resources.map((url, i) => (
                            <a
                              key={i}
                              href={url}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                fontFamily: "'JetBrains Mono', monospace",
                                fontSize: '10px',
                                color: '#4db8ff',
                                textDecoration: 'none',
                              }}
                            >
                              <ExternalLink size={9} />
                              {url}
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
