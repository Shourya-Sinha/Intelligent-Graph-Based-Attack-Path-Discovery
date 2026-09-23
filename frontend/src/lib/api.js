import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

export const startScan = (payload) => api.post('/api/scan/start', payload).then(r=>r.data)
export const bulkScan = (targets, mode="advance", depth=2) => api.post('/api/scan/bulk', {targets, mode, depth}).then(r=>r.data)
export const getScan = (id) => api.get(`/api/scan/${id}`).then(r=>r.data)
export const getScanResults = (id) => api.get(`/api/scan/${id}/results`).then(r=>r.data)
export const listScans = () => api.get('/api/scans').then(r=>r.data)
export const buildGraph = (id) => api.post(`/api/graph/build/${id}`).then(r=>r.data)
export const getGraph = (id) => api.get(`/api/graph/${id}`).then(r=>r.data)
export const riskAnalyze = (payload) => api.post('/api/risk/analyze', payload).then(r=>r.data)
export const aiExplain = (payload) => api.post('/api/ai/explain', payload).then(r=>r.data)
export const aiPrioritize = (jobId) => api.post(`/api/ai/prioritize/${jobId}`).then(r=>r.data)
export const aiChat = (message, job_id=null) => api.post('/api/ai/chat', {message, job_id}).then(r=>r.data)
export const threatFeed = (limit=10) => api.get(`/api/threat-intel/feed?limit=${limit}`).then(r=>r.data)
export const threatCve = (id) => api.get(`/api/threat-intel/cve/${id}`).then(r=>r.data)
export const assetInventory = (jobId) => api.get(`/api/assets/inventory/${jobId}`).then(r=>r.data)
export const assetSbom = (jobId) => api.get(`/api/assets/sbom/${jobId}`).then(r=>r.data)
export const anomaly = (jobId) => api.get(`/api/anomaly/${jobId}`).then(r=>r.data)
export const exportUrl = (jobId, fmt) => `/api/export/${jobId}?format=${fmt}`
export const schedulerList = () => api.get('/api/scheduler/list').then(r=>r.data)
export const schedulerCreate = (payload) => api.post('/api/scheduler/schedule', payload).then(r=>r.data)
export const compliance = (jobId) => api.get(`/api/compliance/${jobId}`).then(r=>r.data)
export const freeInfo = () => api.get('/api/free-info').then(r=>r.data)
export const enterprisePower = () => api.get('/api/enterprise/power').then(r=>r.data)
export const enterpriseTier = () => api.get('/api/enterprise/tier').then(r=>r.data)
export const enterpriseFeatures = () => api.get('/api/enterprise/features').then(r=>r.data)
export const enterpriseIncrease = () => api.get('/api/enterprise/power/how-to-increase').then(r=>r.data)
export const remediationPr = (jobId) => api.get(`/api/remediation/pr/${jobId}`).then(r=>r.data)

export default api
