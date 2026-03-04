import {
  CheckCircle2,
  XCircle,
  Loader2,
  Circle,
  SkipForward,
  ChevronDown,
  ChevronRight,
  Globe,
  ShieldCheck,
  Brain,
  Fingerprint,
  Search,
  Lock,
  Camera,
  AlertTriangle,
  Users,
  Gauge,
  Bug,
} from 'lucide-react'
import { useState } from 'react'
import type { PipelineStep } from '../services/api'

const STEP_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  crawl: Globe,
  rules: ShieldCheck,
  brand: Fingerprint,
  behavioral: Search,
  domain_intel: Search,
  headers: Lock,
  ai: Brain,
  screenshot: Camera,
  threat_intel: AlertTriangle,
  community: Users,
  zeroday: Bug,
  scoring: Gauge,
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-gray-600',
  running: 'text-sky-400',
  done: 'text-emerald-400',
  failed: 'text-red-400',
  skipped: 'text-gray-500',
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'done':
      return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
    case 'running':
      return <Loader2 className="w-4 h-4 text-sky-400 animate-spin shrink-0" />
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400 shrink-0" />
    case 'skipped':
      return <SkipForward className="w-4 h-4 text-gray-500 shrink-0" />
    default:
      return <Circle className="w-4 h-4 text-gray-600 shrink-0" />
  }
}

interface Props {
  steps: PipelineStep[]
  /** When true, show full detail view; when false (during polling), compact */
  expanded?: boolean
}

export default function PipelineSteps({ steps, expanded = false }: Props) {
  const [open, setOpen] = useState(expanded)

  const doneCount = steps.filter(s => s.status === 'done').length
  const runningCount = steps.filter(s => s.status === 'running').length
  const failedCount = steps.filter(s => s.status === 'failed').length
  const total = steps.length

  const summaryParts: string[] = []
  if (doneCount > 0) summaryParts.push(`${doneCount} done`)
  if (runningCount > 0) summaryParts.push(`${runningCount} running`)
  if (failedCount > 0) summaryParts.push(`${failedCount} failed`)
  const summary = summaryParts.join(' · ') || 'Waiting…'

  return (
    <div className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden">
      {/* Header – always visible */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-3 hover:bg-gray-800/40 transition"
      >
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            Pipeline Steps
          </h3>
          <span className="text-xs text-gray-500">
            {summary} ({doneCount}/{total})
          </span>
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-gray-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500" />
        )}
      </button>

      {/* Progress bar */}
      <div className="h-0.5 bg-gray-800">
        <div
          className="h-full bg-gradient-to-r from-sky-500 to-emerald-400 transition-all duration-500 ease-out"
          style={{ width: `${total > 0 ? (doneCount / total) * 100 : 0}%` }}
        />
      </div>

      {/* Steps list */}
      {open && (
        <div className="divide-y divide-gray-800/60">
          {steps.map(step => {
            const Icon = STEP_ICONS[step.name] || ShieldCheck
            return (
              <div
                key={step.name}
                className={`flex items-start gap-3 px-5 py-2.5 transition ${
                  step.status === 'running'
                    ? 'bg-sky-500/5'
                    : step.status === 'failed'
                      ? 'bg-red-500/5'
                      : ''
                }`}
              >
                {/* Left: step icon */}
                <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${STATUS_COLORS[step.status] || 'text-gray-600'}`} />

                {/* Center: label + detail */}
                <div className="flex-1 min-w-0">
                  <p
                    className={`text-sm font-medium ${
                      step.status === 'running'
                        ? 'text-sky-300'
                        : step.status === 'done'
                          ? 'text-gray-300'
                          : step.status === 'failed'
                            ? 'text-red-300'
                            : 'text-gray-500'
                    }`}
                  >
                    {step.label}
                  </p>
                  {step.detail && (
                    <p className="text-xs text-gray-500 mt-0.5 truncate" title={step.detail}>
                      {step.detail}
                    </p>
                  )}
                </div>

                {/* Right: status icon */}
                <StatusIcon status={step.status} />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
