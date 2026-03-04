import { useState, type FormEvent } from 'react'
import { Users, Send, Search, CheckCircle, AlertTriangle, XOctagon, Loader2 } from 'lucide-react'
import { getCommunityConsensus, submitCommunityReport, type CommunityConsensus } from '../services/api'

type Verdict = 'safe' | 'suspicious' | 'phishing'

const verdictConfig: Record<Verdict, { color: string; bg: string; icon: typeof CheckCircle }> = {
  safe: { color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30', icon: CheckCircle },
  suspicious: { color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', icon: AlertTriangle },
  phishing: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', icon: XOctagon },
}

export default function CommunityPage() {
  const [lookupUrl, setLookupUrl] = useState('')
  const [consensus, setConsensus] = useState<CommunityConsensus | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupError, setLookupError] = useState<string | null>(null)

  const [reportUrl, setReportUrl] = useState('')
  const [verdict, setVerdict] = useState<Verdict>('suspicious')
  const [comment, setComment] = useState('')
  const [reportLoading, setReportLoading] = useState(false)
  const [reportSuccess, setReportSuccess] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)

  const handleLookup = async (e: FormEvent) => {
    e.preventDefault()
    if (!lookupUrl.trim()) return
    setLookupLoading(true)
    setLookupError(null)
    setConsensus(null)
    try {
      const data = await getCommunityConsensus(lookupUrl.trim())
      setConsensus(data)
    } catch (err) {
      setLookupError(err instanceof Error ? err.message : 'Lookup failed')
    } finally {
      setLookupLoading(false)
    }
  }

  const handleReport = async (e: FormEvent) => {
    e.preventDefault()
    if (!reportUrl.trim()) return
    setReportLoading(true)
    setReportError(null)
    setReportSuccess(false)
    try {
      await submitCommunityReport(reportUrl.trim(), verdict, comment || undefined)
      setReportSuccess(true)
      setReportUrl('')
      setComment('')
    } catch (err) {
      setReportError(err instanceof Error ? err.message : 'Report failed')
    } finally {
      setReportLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-12 animate-fade-in">
      <div className="text-center mb-12">
        <Users className="w-10 h-10 text-sky-400 mx-auto mb-4" />
        <h1 className="text-3xl font-bold text-white mb-2">Community Intelligence</h1>
        <p className="text-gray-400">
          Look up community consensus on a URL or submit your own report.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Lookup */}
        <section className="bg-gray-900/60 border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Search className="w-5 h-5 text-sky-400" /> Look Up URL
          </h2>
          <form onSubmit={handleLookup} className="space-y-3">
            <input
              type="text"
              value={lookupUrl}
              onChange={e => setLookupUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-4 py-3 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 text-sm"
            />
            <button
              type="submit"
              disabled={lookupLoading || !lookupUrl.trim()}
              className="w-full px-4 py-3 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium text-sm flex items-center justify-center gap-2 transition"
            >
              {lookupLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              Look Up
            </button>
          </form>

          {lookupError && <p className="mt-3 text-sm text-red-400">{lookupError}</p>}

          {consensus && (
            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Domain</span>
                <span className="text-white font-medium">{consensus.consensus.url_or_domain}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Total reports</span>
                <span className="text-white font-medium">{consensus.consensus.total_reports}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Safe / Suspicious / Phishing</span>
                <span className="text-white font-medium">
                  {consensus.consensus.safe_reports} / {consensus.consensus.scam_reports} / {consensus.consensus.phishing_reports}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Crowd risk score</span>
                <span className="text-white font-medium">{consensus.consensus.crowd_risk_score}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Confidence</span>
                <span className="text-white font-medium">{Math.round(consensus.consensus.consensus_confidence * 100)}%</span>
              </div>
            </div>
          )}
        </section>

        {/* Report */}
        <section className="bg-gray-900/60 border border-gray-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Send className="w-5 h-5 text-sky-400" /> Submit Report
          </h2>
          <form onSubmit={handleReport} className="space-y-4">
            <input
              type="text"
              value={reportUrl}
              onChange={e => setReportUrl(e.target.value)}
              placeholder="https://suspicious-site.com"
              className="w-full px-4 py-3 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 text-sm"
            />
            <div>
              <label className="block text-sm text-gray-400 mb-2">Verdict</label>
              <div className="flex gap-2">
                {(Object.keys(verdictConfig) as Verdict[]).map(v => {
                  const cfg = verdictConfig[v]
                  const Icon = cfg.icon
                  const active = verdict === v
                  return (
                    <button
                      key={v}
                      type="button"
                      onClick={() => setVerdict(v)}
                      className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium capitalize transition ${
                        active ? cfg.bg + ' ' + cfg.color : 'border-gray-700 text-gray-400 hover:border-gray-600'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                      {v}
                    </button>
                  )
                })}
              </div>
            </div>
            <textarea
              value={comment}
              onChange={e => setComment(e.target.value)}
              placeholder="Optional comment…"
              rows={3}
              className="w-full px-4 py-3 rounded-lg bg-gray-800 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 text-sm resize-none"
            />
            <button
              type="submit"
              disabled={reportLoading || !reportUrl.trim()}
              className="w-full px-4 py-3 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium text-sm flex items-center justify-center gap-2 transition"
            >
              {reportLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Submit Report
            </button>
          </form>

          {reportError && <p className="mt-3 text-sm text-red-400">{reportError}</p>}
          {reportSuccess && (
            <p className="mt-3 text-sm text-green-400 flex items-center gap-1">
              <CheckCircle className="w-4 h-4" /> Report submitted. Thank you!
            </p>
          )}
        </section>
      </div>
    </div>
  )
}
