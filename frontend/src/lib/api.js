import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

export const startScan = (payload) => api.post('/api/scan/start', payload).then(r=>r.data)
export const getScan = (id) => api.get(`/api/scan/${id}`).then(r=>r.data)
export const getScanResults = (id) => api.get(`/api/scan/${id}/results`).then(r=>r.data)
export const listScans = () => api.get('/api/scans').then(r=>r.data)
export const buildGraph = (id) => api.post(`/api/graph/build/${id}`).then(r=>r.data)
export const getGraph = (id) => api.get(`/api/graph/${id}`).then(r=>r.data)
export const riskAnalyze = (payload) => api.post('/api/risk/analyze', payload).then(r=>r.data)
export const aiExplain = (payload) => api.post('/api/ai/explain', payload).then(r=>r.data)
export const aiPrioritize = (jobId) => api.post(`/api/ai/prioritize/${jobId}`).then(r=>r.data)
export const exportUrl = (jobId, fmt) => `/api/export/${jobId}?format=${fmt}`

export default api
