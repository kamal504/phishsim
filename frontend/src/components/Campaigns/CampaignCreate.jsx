import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createCampaign } from '../../api'

const TEMPLATE_BODY = `Dear {{name}},

We have detected unusual sign-in activity on your corporate account. To secure your account, please verify your identity immediately.

<a href="{{phishing_link}}">👉 Verify Your Account Now</a>

This link will expire in 24 hours.

<img src="{{tracking_pixel}}" width="1" height="1">

IT Security Team`

const s = {
  page: { maxWidth: 720, display: 'flex', flexDirection: 'column', gap: 28 },
  title: { fontSize: 24, fontWeight: 700, color: '#f1f5f9' },
  card: { background: '#141720', border: '1px solid #1e2232', borderRadius: 12, padding: 28 },
  sectionTitle: { fontSize: 14, fontWeight: 600, color: '#94a3b8', marginBottom: 18, textTransform: 'uppercase', letterSpacing: '0.05em' },
  row: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 },
  field: { display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 },
  label: { fontSize: 13, fontWeight: 500, color: '#94a3b8' },
  input: {
    background: '#0f1117', border: '1px solid #1e2232', borderRadius: 8,
    padding: '10px 12px', color: '#e2e8f0', fontSize: 14, outline: 'none',
    transition: 'border-color 0.15s',
  },
  textarea: {
    background: '#0f1117', border: '1px solid #1e2232', borderRadius: 8,
    padding: '10px 12px', color: '#e2e8f0', fontSize: 13, outline: 'none',
    resize: 'vertical', minHeight: 180, lineHeight: 1.6,
  },
  hint: { fontSize: 11, color: '#475569', marginTop: 4 },
  actions: { display: 'flex', gap: 12 },
  btn: (variant = 'primary') => ({
    padding: '10px 22px', borderRadius: 9, border: 'none', fontWeight: 600,
    fontSize: 14, cursor: 'pointer',
    background: variant === 'primary' ? '#6366f1' : '#1e2232',
    color: '#fff', transition: 'opacity 0.15s',
  }),
  error: { color: '#ef4444', fontSize: 13, padding: '10px 14px', background: 'rgba(239,68,68,0.1)', borderRadius: 8 },
}

export default function CampaignCreate() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    name: '',
    description: '',
    subject: '',
    body: TEMPLATE_BODY,
    from_email: 'it-security@company.com',
    from_name: 'IT Security Team',
    phishing_url: 'http://localhost:8000',
  })
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const set = (key) => (e) => setForm(f => ({ ...f, [key]: e.target.value }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.name || !form.subject || !form.body) {
      setError('Name, Subject, and Body are required.')
      return
    }
    setSaving(true)
    try {
      const campaign = await createCampaign(form)
      navigate(`/campaigns/${campaign.id}`)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create campaign')
      setSaving(false)
    }
  }

  return (
    <div style={s.page}>
      <div>
        <h1 style={s.title}>New Campaign</h1>
        <p style={{ color: '#64748b', fontSize: 14, marginTop: 4 }}>Configure your phishing simulation</p>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {error && <div style={s.error}>{error}</div>}

        {/* Basic Info */}
        <div style={s.card}>
          <div style={s.sectionTitle}>Campaign Details</div>
          <div style={s.row}>
            <div style={s.field}>
              <label style={s.label}>Campaign Name *</label>
              <input style={s.input} value={form.name} onChange={set('name')} placeholder="Q2 Credential Harvest Test" />
            </div>
            <div style={s.field}>
              <label style={s.label}>Description</label>
              <input style={s.input} value={form.description} onChange={set('description')} placeholder="Optional description" />
            </div>
          </div>
        </div>

        {/* Email Settings */}
        <div style={s.card}>
          <div style={s.sectionTitle}>Email Configuration</div>
          <div style={s.row}>
            <div style={s.field}>
              <label style={s.label}>From Name *</label>
              <input style={s.input} value={form.from_name} onChange={set('from_name')} placeholder="IT Security Team" />
            </div>
            <div style={s.field}>
              <label style={s.label}>From Email *</label>
              <input style={s.input} type="email" value={form.from_email} onChange={set('from_email')} placeholder="it-security@company.com" />
            </div>
          </div>
          <div style={s.field}>
            <label style={s.label}>Subject Line *</label>
            <input style={s.input} value={form.subject} onChange={set('subject')} placeholder="[ACTION REQUIRED] Verify your account immediately" />
          </div>
          <div style={s.field}>
            <label style={s.label}>Phishing / Redirect URL</label>
            <input style={s.input} value={form.phishing_url} onChange={set('phishing_url')} placeholder="http://localhost:8000" />
            <span style={s.hint}>Targets who click will land on the fake login page at this host.</span>
          </div>
          <div style={s.field}>
            <label style={s.label}>Email Body *</label>
            <textarea style={s.textarea} value={form.body} onChange={set('body')} />
            <span style={s.hint}>
              Placeholders: <code style={{ color: '#818cf8' }}>{'{{name}}'}</code> — recipient name &nbsp;·&nbsp;
              <code style={{ color: '#818cf8' }}>{'{{phishing_link}}'}</code> — tracked link &nbsp;·&nbsp;
              <code style={{ color: '#818cf8' }}>{'{{tracking_pixel}}'}</code> — open tracker
            </span>
          </div>
        </div>

        <div style={s.actions}>
          <button type="submit" style={s.btn('primary')} disabled={saving}>
            {saving ? 'Creating…' : '✓ Create Campaign'}
          </button>
          <button type="button" style={s.btn('secondary')} onClick={() => navigate('/campaigns')}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  )
}
