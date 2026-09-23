import { useEffect, useRef, useState } from 'react'
import { wsUrl } from '../lib/ws'

export function useScanWebSocket(jobId, onMessage) {
  const wsRef = useRef(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    if (!jobId) return
    const url = wsUrl(`/ws/scan/${jobId}`)
    const ws = new WebSocket(url)
    wsRef.current = ws
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)
    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data)
        onMessage?.(data)
      } catch {}
    }
    return () => { try{ ws.close() } catch{} }
  }, [jobId])

  return { connected }
}

export function useGlobalWebSocket(onMessage) {
  const [connected, setConnected] = useState(false)
  useEffect(() => {
    const url = wsUrl(`/ws/global`)
    const ws = new WebSocket(url)
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (ev) => {
      try { onMessage?.(JSON.parse(ev.data)) } catch {}
    }
    return () => { try{ws.close()}catch{}}
  }, [])
  return { connected }
}
