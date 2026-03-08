import { useState, useEffect, useRef, useCallback } from 'react'
import { getAnalysis, type AnalysisResult } from '../services/api'

/**
 * Polls an analysis by ID until it reaches a terminal state (completed/failed).
 */
export function useAnalysisPolling(analysisId: string | null, intervalMs = 1500) {
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!analysisId) return

    setLoading(true)
    setError(null)
    setResult(null)

    const poll = async () => {
      try {
        const data = await getAnalysis(analysisId)
        setResult(data)

        if (data.status === 'completed' || data.status === 'failed') {
          stopPolling()
          setLoading(false)
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Polling failed')
        stopPolling()
        setLoading(false)
      }
    }

    // Poll immediately, then on interval
    poll()
    timerRef.current = setInterval(poll, intervalMs)

    return stopPolling
  }, [analysisId, intervalMs, stopPolling])

  return { result, error, loading }
}
