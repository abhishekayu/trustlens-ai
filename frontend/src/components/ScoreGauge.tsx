interface ScoreGaugeProps {
  score: number | null
  size?: number
}

function getScoreColor(score: number): string {
  if (score >= 75) return '#22c55e'
  if (score >= 50) return '#eab308'
  if (score >= 25) return '#f97316'
  return '#ef4444'
}

function getRiskLabel(score: number): string {
  if (score >= 75) return 'Safe'
  if (score >= 50) return 'Low Risk'
  if (score >= 25) return 'Suspicious'
  return 'High Risk'
}

export default function ScoreGauge({ score, size = 180 }: ScoreGaugeProps) {
  if (score === null || score === undefined) {
    return (
      <div className="flex items-center justify-center" style={{ width: size, height: size }}>
        <div className="w-16 h-16 border-4 border-gray-700 border-t-sky-400 rounded-full animate-spin" />
      </div>
    )
  }

  const radius = 45
  const circumference = 2 * Math.PI * radius
  const progress = Math.max(0, Math.min(100, score)) / 100
  const dashOffset = circumference * (1 - progress)
  const color = getScoreColor(score)
  const label = getRiskLabel(score)

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} viewBox="0 0 100 100" className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="#1f2937"
          strokeWidth="8"
        />
        {/* Progress circle */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{
            transition: 'stroke-dashoffset 1s ease-out, stroke 0.5s ease',
            filter: `drop-shadow(0 0 6px ${color}40)`,
          }}
        />
        {/* Score text */}
        <text
          x="50" y="50"
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-white font-bold"
          style={{ fontSize: '22px', transform: 'rotate(90deg)', transformOrigin: '50% 50%' }}
        >
          {Math.round(score)}
        </text>
      </svg>
      <div className="text-center">
        <span
          className="text-sm font-semibold px-3 py-1 rounded-full"
          style={{ backgroundColor: `${color}20`, color }}
        >
          {label}
        </span>
      </div>
    </div>
  )
}
