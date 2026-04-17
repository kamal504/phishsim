import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  getCampaign, getTargets, addTarget, addTargetsBulk, removeTarget,
  launchCampaign, completeCampaign, simulateEvents, getFunnel
} from '../../api'
import FunnelChart from '../Dashboard/FunnelChart'

const STATUS_COLORS = { draft: '#94a3b8', active: '#22c55e', completed: '#6366f1' }

const s = {
  page: { display: 'flex', flexDirection: 'column', gap: 24 },
  header: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 },
  title: { fontSize: 24, fontWeight: 700, color: '#f1f5f9' },
  pill: (status) => ({
    display: 'inline-block', padding: '4px 12px', borderRadius: 20,
    fontSize: 12, fontWeight: 600, color: STATUS_COLORS[status] || '#94a3b8',
    background: `${STATUS_COLORS[status]}20` || 'rgba(148,163,184,0.1)',
    marginLeft: 10,
  }),
  actions: { display: 'flex', gap: 10, flexWrap: 'wrap' },
  btn: (variant = 'primary') => ({
    padding: '8px 18px', borderRadius: 9, border: 'none', fontWeight: 600,
    fontSize: 13, cursor: 'pointer', transition: 'opacity 0.15s',
    background: variant === 'primary' ? '#6366f1'
      : variant === 'success' ? '#16a34a'
      : variant === 'warning' ? '#d97706'
      : variant === 'danger'  ? 'rgba(239,68,68,0.15)'
      : '#1e2232',
    color: variant === 'danger' ? '#ef4444' : '#fff',
  }),
  grid2: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 },
  card: { background: '#141720', border: '1px solid #1e2232', borderRadius: 12, padding: 22 },
  cardTitle: { fontSize: 14, fontWeight: 600, color: '#94a3b8', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.04em' },
  meta: { display: 'flex', flexDirection: 'column', gap: 10 },
  metaRow: { display: 'flex', justifyContent: 'space-between', fontSize: 13, borderBottom: '1px solid #1e2232', paddingBottom: 8 },
  metaKey: { color: '#64748b' },
  metaVal: { color: '#e2e8f0', fontWeight: 500 },
  input: { background: '#0f1117', border: '1px solid #1e2232', borderRadius: 7, padding: '8px 10px', color: '#e2e8f0', fontSize: 13, outline: 'none', width: '100%' },
  addForm: { display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 },
  targetRow: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #1e2232' },
  notice: { background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 10, padding: '12px 16px', fontSize: 13, color: '#818cf8' },
  toast: (color) => ({
    background: color === 'green' ? 'rgba(22,163,74,0.15)' : 'rgba(239,68,68,0.15)',
    border: `1px solid ${color === 'green' ? '#16a34a' : '#ef4444'}`,
    borderRadius: 9, padding: '10px 14px', fontSize: 13,
    color: color === 'green' ? '#4ade80' : '#f87171',
  }),
}

const BULK_PLACEHOLDER = `john.doe@company.com,John Doe,Engineering
jane.smith@company.com,Jane Smith,Finance
bob.jones@company.com,Bob Jones,HR`

export default function CampaignDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [campaign, setCampaign] = useState(null)
  const [targets, setTargets] = useState([])
  const [newTarget, setNewTarget] = useState({ email: '', name: '', department: '' })
  const [bulkText, setBulkText] = useState('')
  const [showBulk, setShowBulk] = useState(false)
  const [toast, setToast] = useState(null)
  const [loading, setLoading] = useState(true)

  const showToast = (msg, color = 'green') => {
    setToast({ msg, color })
    setTimeout(() => setToast(null), 3000)
  }

  const load = () => {
    Promise.all([getCampaign(id), getTargets(id)]).then(([c, t]) => {
      setCampaign(c); setTargets(t); setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(load, [id])

  const handleAddTarget = async () => {
    if (!newTarget.email || !newTarget.name) return
    await addTarget(id, { ...newTarget, department: newTarget.department || 'Unknown' })
    setNewTarget({ email: '', name: '', department: '' })
    load()
    showToast('Target added')
  }

  const handleBulkAdd = async () => {
    const lines = bulkText.trim().split('\n').filter(Boolean)
    const parsed = lines.map(line => {
      const [email, name, department] = line.split(',').map(s => s.trim())
      return { email, name: name || email, department: department || 'Unknown' }
    }).filter(t => t.email)
    if (!parsed.length) return
    await addTargetsBulk(id, parsed)
    setBulkText(''); setShowBulk(false)
    load()
    showToast(`${parsed.length} targets added`)
  }

  const handleRemoveTarget = async (targetId) => {
    await removeTarget(id, targetId)
    load()
    showToast('Target removed')
  }

  const handleLaunch = async () => {
    try {
      await launchCampaign(id); load(); showToast('Campaign launched! Emails marked as sent & delivered.')
    } catch (e) { showToast(e.response?.data?.detail || 'Launch failed', 'red') }
  }

  const handleComplete = async () => {
    await completeCampaign(id); load(); showToast('Campaign marked as completed')
  }

  const handleSimulate = async () => {
    try {
      const res = await simulateEvents(id); load(); showToast(res.message)
    } catch (e) { showToast(e.response?.data?.detail || 'Simulation failed', 'red') }
  }

  if (loading) return <div style={{ color: '#64748b', padding: 40, textAlign: 'center' }}>Loading…</div>
  if (!campaign) return <div style={{ color: '#64748b', padding: 40 }}>Campaign not found</div>

  return (
    <div style={s.page}>
      {/* Header */}
      <div style={s.header}>
        <div>
          <button style={{ ...s.btn('secondary'), fontSize: 12, marginBottom: 10 }} onClick={() => navigate('/campaigns')}>
            ← Back
          </button>
          <h1 style={s.title}>
            {campaign.name}
            <span style={s.pill(campaign.status)}>{campaign.status.toUpperCase()}</span>
          </h1>
          <p style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>{campaign.description || 'No description'}</p>
        </div>
        <div style={s.actions}>
          {campaign.status === 'draft' && (
            <button style={s.btn('success')} onClick={handleLaunch} disabled={targets.length === 0}>
              🚀 Launch Campaign
            </button>
          )}
          {campaign.status === 'active' && (
            <>
              <button style={s.btn('warning')} onClick={handleSimulate}>
                ⚡ Simulate Events
              </button>
              <button style={s.btn('secondary')} onClick={handleComplete}>
                ✅ Mark Complete
              </button>
            </>
          )}
        </div>
      </div>

      {toast && <div style={s.toast(toast.color)}>{toast.msg}</div>}

      {campaign.status === 'draft' && targets.length === 0 && (
        <div style={s.notice}>
          📌 Add targets below, then launch the campaign to begin the simulation.
        </div>
      )}

      {/* Meta + Funnel */}
      <div style={s.grid2}>
        <div style={s.card}>
          <div style={s.cardTitle}>Campaign Info</div>
          <div style={s.meta}>
            <div style={s.metaRow}><span style={s.metaKey}>From</span><span style={s.metaVal}>{campaign.from_name} &lt;{campaign.from_email}&gt;</span></div>
            <div style={s.metaRow}><span style={s.metaKey}>Subject</span><span style={s.metaVal}>{campaign.subject}</span></div>
            <div style={s.metaRow}><span style={s.metaKey}>Phishing URL</span><span style={s.metaVal}>{campaign.phishing_url}</span></div>
            <div style={s.metaRow}><span style={s.metaKey}>Total Targets</span><span style={s.metaVal}>{targets.length}</span></div>
            <div style={s.metaRow}><span style={s.metaKey}>Created</span><span style={s.metaVal}>{new Date(campaign.created_at).toLocaleString()}</span></div>
            {campaign.launched_at && <div style={s.metaRow}><span style={s.metaKey}>Launched</span><span style={s.metaVal}>{new Date(campaign.launched_at).toLocaleString()}</span></div>}
          </div>
        </div>

        <div style={s.card}>
          <div style={s.cardTitle}>Delivery Funnel</div>
          {campaign.status !== 'draft' ? <FunnelChart campaignId={id} /> : (
            <div style={{ color: '#64748b', fontSize: 13, padding: '20px 0' }}>Launch the campaign to see funnel data</div>
          )}
        </div>
      </div>

      {/* Tracking links info */}
      {campaign.status !== 'draft' && targets.length > 0 && (
        <div style={s.card}>
          <div style={s.cardTitle}>Tracking URLs (Example)</div>
          <div style={{ fontSize: 12, color: '#64748b', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div><span style={{ color: '#818cf8' }}>Pixel:</span> <code style={{ color: '#94a3b8' }}>http://localhost:8000/track/pixel/{'{'}{targets[0]?.tracking_token}{'}'}</code></div>
            <div><span style={{ color: '#818cf8' }}>Click:</span> <code style={{ color: '#94a3b8' }}>http://localhost:8000/track/click/{'{'}{targets[0]?.tracking_token}{'}'}</code></div>
            <div><span style={{ color: '#818cf8' }}>Landing:</span> <code style={{ color: '#94a3b8' }}>http://localhost:8000/phish/{'{'}{targets[0]?.tracking_token}{'}'}</code></div>
          </div>
        </div>
      )}

      {/* Targets */}
      <div style={s.card}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={s.cardTitle}>Targets ({targets.length})</div>
          {campaign.status === 'draft' && (
            <button style={{ ...s.btn('secondary'), fontSize: 12 }} onClick={() => setShowBulk(v => !v)}>
              {showBulk ? 'Single Add' : '📋 Bulk Import'}
            </button>
          )}
        </div>

        {campaign.status === 'draft' && !showBulk && (
          <div style={s.addForm}>
            <input style={{ ...s.input, flex: '2 1 160px' }} placeholder="Email *" value={newTarget.email} onChange={e => setNewTarget(v => ({ ...v, email: e.target.value }))} />
            <input style={{ ...s.input, flex: '2 1 120px' }} placeholder="Name *" value={newTarget.name} onChange={e => setNewTarget(v => ({ ...v, name: e.target.value }))} />
            <input style={{ ...s.input, flex: '1 1 100px' }} placeholder="Department" value={newTarget.department} onChange={e => setNewTarget(v => ({ ...v, department: e.target.value }))} />
            <button style={s.btn('primary')} onClick={handleAddTarget}>Add</button>
          </div>
        )}

        {showBulk && campaign.status === 'draft' && (
          <div style={{ marginBottom: 16 }}>
            <textarea
              style={{ ...s.input, minHeight: 100, resize: 'vertical', lineHeight: 1.6, marginBottom: 8 }}
              placeholder={BULK_PLACEHOLDER}
              value={bulkText}
              onChange={e => setBulkText(e.target.value)}
            />
            <div style={{ fontSize: 11, color: '#475569', marginBottom: 8 }}>One per line: email, name, department</div>
            <button style={s.btn('primary')} onClick={handleBulkAdd}>Import All</button>
          </div>
        )}

        {targets.length === 0 ? (
          <div style={{ color: '#64748b', fontSize: 13, padding: '12px 0' }}>No targets yet. Add emails above.</div>
        ) : (
          <div style={{ maxHeight: 340, overflowY: 'auto' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.5fr 1fr auto', gap: 8, padding: '0 0 8px 0', borderBottom: '1px solid #1e2232', marginBottom: 4 }}>
              {['Email', 'Name', 'Department', ''].map(h => (
                <span key={h} style={{ fontSize: 11, color: '#64748b', fontWeight: 600, textTransform: 'uppercase' }}>{h}</span>
              ))}
            </div>
            {targets.map(t => (
              <div key={t.id} style={{ display: 'grid', gridTemplateColumns: '2fr 1.5fr 1fr auto', gap: 8, alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #0f1117' }}>
                <span style={{ fontSize: 13, color: '#94a3b8' }}>{t.email}</span>
                <span style={{ fontSize: 13, color: '#e2e8f0' }}>{t.name}</span>
                <span style={{ fontSize: 12, color: '#64748b' }}>{t.department}</span>
                {campaign.status === 'draft' && (
                  <button
                    style={{ padding: '3px 8px', borderRadius: 6, border: 'none', background: 'rgba(239,68,68,0.1)', color: '#ef4444', fontSize: 12, cursor: 'pointer' }}
                    onClick={() => handleRemoveTarget(t.id)}
                  >✕</button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
