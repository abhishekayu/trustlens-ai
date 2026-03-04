interface EvidenceTimelineProps {
  signals: string | null
}

interface ParsedSignal {
  label: string
  detail: string
  severity: 'safe' | 'low' | 'medium' | 'high'
}

function parseSignals(raw: string): ParsedSignal[] {
  // signals_summary is typically a multi-line or semicolon-separated string
  const lines = raw.split(/[;\n]/).map(s => s.trim()).filter(Boolean)
  return lines.map(line => {
    const severity = (() => {
      const lower = line.toLowerCase()
      if (lower.includes('safe') || lower.includes('no risk') || lower.includes('✓')) return 'safe' as const
      if (lower.includes('high') || lower.includes('critical') || lower.includes('phish') || lower.includes('threat')) return 'high' as const
      if (lower.includes('suspicious') || lower.includes('warning')) return 'medium' as const
      return 'low' as const
    })()

    const parts = line.split(':')
    return {
      label: parts[0]?.trim() || 'Signal',
      detail: parts.slice(1).join(':').trim() || line,
      severity,
    }
  })
}

const severityColors = {
  safe: 'bg-green-500',
  low: 'bg-yellow-500',
  medium: 'bg-orange-500',
  high: 'bg-red-500',
}

const severityBg = {
  safe: 'bg-green-500/10 border-green-500/20',
  low: 'bg-yellow-500/10 border-yellow-500/20',
  medium: 'bg-orange-500/10 border-orange-500/20',
  high: 'bg-red-500/10 border-red-500/20',
}

export default function EvidenceTimeline({ signals }: EvidenceTimelineProps) {
  if (!signals) return null

  const parsed = parseSignals(signals)
  if (parsed.length === 0) return null

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Evidence Timeline</h3>
      <div className="space-y-2">
        {parsed.map((signal, i) => (
          <div
            key={i}
            className={`flex items-start gap-3 p-3 rounded-lg border ${severityBg[signal.severity]} animate-fade-in`}
            style={{ animationDelay: `${i * 60}ms` }}
          >
            <div className="flex flex-col items-center mt-1">
              <div className={`w-2.5 h-2.5 rounded-full ${severityColors[signal.severity]}`} />
              {i < parsed.length - 1 && <div className="w-px h-6 bg-gray-700 mt-1" />}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-200">{signal.label}</p>
              <p className="text-xs text-gray-400 mt-0.5">{signal.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
