import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { getCampaigns, deleteCampaign } from '../../api'

const STATUS_STYLES = {
  draft:     { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', label: '✏️ Draft' },
  active:    { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',   label: '🟢 Active' },
  completed: { color: '#6366f1', bg: 'rgba(99,102,241,0.1)', label: '✅ Completed' },
}

const s = {
  page: { display: 'flex', flexDirection: 'column', gap: 24 },
  header: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  title: { fontSize: 26, fontWeight: 700, color: '#f1f5f9' },
  btn: (variant = 'primary') => ({
    padding: '9px 18px',
    borderRadius: 9,
    border: 'none',
    fontWeight: 600,
    fontSize: 14,
    cursor: 'pointer',
    background: variant === 'primary' ? '#6366f1' : variant === 'danger' ? 'rgba(220,38,38,0.15)' : '#1e2232',
    color: variant === 'danger' ? '#ef4444' : '#fff',
    transition: 'opacity 0.15s',
  }),
  table: {
    width: '100%',
    borderCollapse: 'separate',
    borderSpacing: '0 8px',
  },
  th: {
    textAlign: 'left',
    padding: '6px 16px',
    fontSize: 11,
    fontWeight: 600,
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  },
  td: {
    padding: '14px 16px',
    background: '#141720',
    fontSize: 14,
    color: '#e2e8f0',
    verticalAlign: 'middle',
  },
  pill: (status) => ({
    display: 'inline-block',
    padding: '3px 10px',
    borderRadius: 20,
    fontSize: 12,
    fontWeight: 600,
    color: STATUS_STYLES[status]?.color || '#94a3b8',
    background: STATUS_STYLES[status]?.bg || 'rgba(148,163,184,0.1)',
  }),
  empty: {
    textAlign: 'center', padding: '60px 20px', color: '#64748b', fontSize: 14,
  }
}

export default function CampaignList() {
  const navigate = useNavigate()
  const [campaigns, setCampaigns] = useState([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    getCampaigns().then(d => { setCampaigns(d); setLoading(false) }).catch(() => setLoading(false))
  }

  useEffect(load, [])

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Delete campaign "${name}"? This cannot be undone.`)) return
    await deleteCampaign(id)
    load()
  }

  return (
    <div style={s.page}>
      <div style={s.header}>
        <div>
          <h1 style={s.title}>Campaigns</h1>
          <p style={{ color: '#64748b', fontSize: 14, marginTop: 4 }}>Manage your phishing simulations</p>
        </div>
        <button style={s.btn('primary')} onClick={() => navigate('/campaigns/new')}>
          + New Campaign
        </button>
      </div>

      {loading ? (
        <div style={s.empty}>Loading campaigns…</div>
      ) : campaigns.length === 0 ? (
        <div style={s.empty}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>📭</div>
          <div style={{ fontWeight: 600, marginBottom: 8, color: '#94a3b8' }}>No campaigns yet</div>
          <div style={{ marginBottom: 20 }}>Create your first phishing simulation to get started.</div>
          <button style={s.btn('primary')} onClick={() => navigate('/campaigns/new')}>
            Create Campaign
          </button>
        </div>
      ) : (
        <table style={s.table}>
          <thead>
            <tr>
              {['Campaign Name', 'Status', 'From', 'Created', 'Actions'].map(h => (
                <th key={h} style={s.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {campaigns.map((c, i) => (
              <tr key={c.id}>
                <td style={{ ...s.td, borderRadius: i === campaigns.length - 1 ? '0 0 0 10px' : 0, borderTopLeftRadius: 10, borderBottomLeftRadius: 10 }}>
                  <div style={{ fontWeight: 600 }}>{c.name}</div>
                  <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>{c.subject}</div>
                </td>
                <td style={s.td}>
                  <span style={s.pill(c.status)}>{STATUS_STYLES[c.status]?.label || c.status}</span>
                </td>
                <td style={s.td}>
                  <div style={{ fontSize: 13 }}>{c.from_name}</div>
                  <div style={{ fontSize: 12, color: '#64748b' }}>{c.from_email}</div>
                </td>
                <td style={s.td}>
                  <div style={{ fontSize: 13, color: '#94a3b8' }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </div>
                </td>
                <td style={{ ...s.td, borderTopRightRadius: 10, borderBottomRightRadius: 10 }}>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button style={s.btn('secondary')} onClick={() => navigate(`/campaigns/${c.id}`)}>
                      View
                    </button>
                    <button style={s.btn('danger')} onClick={() => handleDelete(c.id, c.name)}>
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
