import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

// ── Campaigns ─────────────────────────────────────────────────
export const getCampaigns = () => api.get('/campaigns').then(r => r.data)
export const getCampaign = (id) => api.get(`/campaigns/${id}`).then(r => r.data)
export const createCampaign = (data) => api.post('/campaigns', data).then(r => r.data)
export const updateCampaign = (id, data) => api.put(`/campaigns/${id}`, data).then(r => r.data)
export const deleteCampaign = (id) => api.delete(`/campaigns/${id}`)
export const launchCampaign = (id) => api.post(`/campaigns/${id}/launch`).then(r => r.data)
export const completeCampaign = (id) => api.post(`/campaigns/${id}/complete`).then(r => r.data)
export const simulateEvents = (id) => api.post(`/campaigns/${id}/simulate`).then(r => r.data)
export const getCampaignEvents = (id) => api.get(`/campaigns/${id}/events`).then(r => r.data)

// ── Targets ───────────────────────────────────────────────────
export const getTargets = (campaignId) => api.get(`/campaigns/${campaignId}/targets`).then(r => r.data)
export const addTarget = (campaignId, data) => api.post(`/campaigns/${campaignId}/targets`, data).then(r => r.data)
export const addTargetsBulk = (campaignId, data) => api.post(`/campaigns/${campaignId}/targets/bulk`, data).then(r => r.data)
export const removeTarget = (campaignId, targetId) => api.delete(`/campaigns/${campaignId}/targets/${targetId}`)

// ── Analytics ─────────────────────────────────────────────────
export const getOverview = () => api.get('/analytics/overview').then(r => r.data)
export const getFunnel = (campaignId) => api.get(`/analytics/funnel/${campaignId}`).then(r => r.data)
export const getRiskyUsers = () => api.get('/analytics/risky-users').then(r => r.data)
export const getDepartments = () => api.get('/analytics/departments').then(r => r.data)
export const getTrends = () => api.get('/analytics/trends').then(r => r.data)
