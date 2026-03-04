import { Shield, AlertTriangle, XOctagon, CheckCircle, type LucideIcon } from 'lucide-react'

interface SignalCardProps {
  title: string
  score: number | null
  evidence?: string
  icon?: LucideIcon
}

function getColor(score: number) {
  if (score >= 75) return { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400' }
  if (score >= 50) return { bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400' }
  if (score >= 25) return { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400' }
  return { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400' }
}

function getIcon(score: number): LucideIcon {
  if (score >= 75) return CheckCircle
  if (score >= 50) return Shield
  if (score >= 25) return AlertTriangle
  return XOctagon
}

export default function SignalCard({ title, score, evidence, icon }: SignalCardProps) {
  if (score === null || score === undefined) return null

  const colors = getColor(score)
  const Icon = icon || getIcon(score)

  return (
    <div className={`rounded-xl border ${colors.border} ${colors.bg} p-4 animate-fade-in`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <Icon className={`w-4 h-4 ${colors.text}`} />
          <h4 className="text-sm font-medium text-gray-200">{title}</h4>
        </div>
        <span className={`text-lg font-bold ${colors.text}`}>{Math.round(score)}</span>
      </div>
      {evidence && (
        <p className="text-xs text-gray-400 leading-relaxed mt-1">{evidence}</p>
      )}
    </div>
  )
}
