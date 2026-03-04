import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Search, Zap, Eye, Brain, ArrowRight, Loader2 } from 'lucide-react'
import { submitAnalysis } from '../services/api'

const features = [
  {
    icon: Eye,
    title: 'Visual Similarity',
    desc: 'Screenshot comparison detects cloned pages that text analysis misses.',
  },
  {
    icon: Brain,
    title: 'AI‑Assisted',
    desc: 'Local LLM reasoning with a hard 30% weight cap. Rules always govern.',
  },
  {
    icon: Zap,
    title: 'Zero‑Day Detection',
    desc: 'Anomaly scoring catches brand‑new threats before blocklists update.',
  },
]

export default function ScanPage() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)

    try {
      let normalised = url.trim()
      if (!/^https?:\/\//i.test(normalised)) normalised = `https://${normalised}`

      const res = await submitAnalysis(normalised)
      navigate(`/results/${res.analysis_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submission failed')
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-16 animate-fade-in">
      {/* Hero */}
      <div className="text-center mb-12">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-sky-500/15 mb-6">
          <Shield className="w-8 h-8 text-sky-400" />
        </div>
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white mb-4">
          Trust, <span className="text-sky-400">verified.</span>
        </h1>
        <p className="text-gray-400 text-lg max-w-xl mx-auto">
          Paste any URL below and get an explainable trust score in seconds.
          AI advises. Rules decide. Evidence explains everything.
        </p>
      </div>

      {/* Search form */}
      <form onSubmit={handleSubmit} className="mb-8">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="Enter URL to analyze, e.g. https://example.com"
              className="w-full pl-12 pr-4 py-4 rounded-xl bg-gray-900 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500 transition text-base"
              disabled={loading}
              autoFocus
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-4 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold flex items-center gap-2 transition whitespace-nowrap"
          >
            {loading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Scanning…
              </>
            ) : (
              <>
                Analyze
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
        {error && (
          <p className="mt-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2">
            {error}
          </p>
        )}
      </form>

      {/* Feature cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-16">
        {features.map(({ icon: Icon, title, desc }) => (
          <div
            key={title}
            className="rounded-xl border border-gray-800 bg-gray-900/50 p-5 hover:border-gray-700 transition"
          >
            <Icon className="w-6 h-6 text-sky-400 mb-3" />
            <h3 className="font-semibold text-white mb-1">{title}</h3>
            <p className="text-sm text-gray-400 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>

      {/* Trust badge */}
      <div className="text-center mt-16 text-xs text-gray-600">
        <p>Open‑source &bull; Self‑hostable &bull; No data leaves your infra</p>
      </div>
    </div>
  )
}
