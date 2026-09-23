export function wsUrl(path) {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = location.host
  // In dev, vite proxies /ws to backend, but ws needs direct backend host when preview
  // Try same host with backend port fallback via env
  const apiHost = import.meta.env.VITE_WS_URL
  if (apiHost) return `${apiHost}${path}`
  // use current host and assume backend same origin (proxy handles via ws)
  return `${proto}//${host}${path}`
}
