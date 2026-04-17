import { useState, useEffect } from 'react'
import { getOverview, getCampaigns } from '../../api'
import FunnelChart from './FunnelChart'
import RiskyUsers from './RiskyUsers'
import DepartmentHeatmap from './DepartmentHeatmap'
import TrendChart from './TrendChart'

const s = {
  page: { display: 'flex', flexDirection: 'column', gap: 28 },
  header: { display: 'flex', flexDirection: 'column', gap: 4 },
  title: { fontSize: 26, fontWeight: 700, color: '#f1f5f9' },
  subtitle: { fontSize: 14, color: '#64748b' },
  statsRow: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 },
  statCard: (color) => ({
    background: '#141720',
    border: `1px solid #1e2232`,
    borderRadius: 12,
    padding: '20px 22px',
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
    borderLeft: `3px solid ${color}`,
  }),
  statLabel: { fontSize: 12, color: '#64748b', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em' },
  statValue: { fontSize: 28, fontWeight: 700, color: '#f1f5f9' },
  statSub: (color) => ({ fontSize: 13, color, fontWeight: 600 }),
  grid2: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 },
  grid1: { display: 'grid', gridTemplateColumns: '1fr', gap: 20 },
  card: {
    background: '#141720',
    border: '1px solid #1e2232',
    borderRadius: 12,
    padding: '22px 24px',
  },
  cardTitle: { fontSize: 15, fontWeight: 600, color: '#e2e8f0', marginBottom: 18 },
  select: {
    background: '#0f1117',
    border: '1px solid #1e2232',
    color: '#e2e8f0',
    borderRadius: 8,
    padding: '5px 10px',
    fontSize: 13,
    marginLeft: 12,
  },
  row: { display: 'flex', alignItems: 'center' },
}

function StatCard({ label, value, sub, subColor = '#6366f1', accentColor = '#6366f1' }) {
  return (
    <div style={s.statCard(accentColor)}>
      <span style={s.statLabel}>{label}</span>
      <span style={s.statValue}>{value}</span>
      {sub && <span style={s.statSub(subColor)}>{sub}</span>}
    </div>
  )
}

export default function Dashboard() {
  const [overview, setOverview] = useState(null)
  const [campaigns, setCampaigns] = useState([])
  const [selectedCampaign, setSelectedCampaign] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getOverview(), getCampaigns()]).then(([ov, camp]) => {
      setOverview(ov)
      setCampaigns(camp)
      const active = camp.find(c => c.status === 'active') || camp[0]
      if (active) setSelectedCampaign(String(active.id))
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ color: '#64748b', padding: 40, textAlign: 'center' }}>Loading dashboard…</div>

  return (
    <div style={s.page}>
      <div style={s.header}>
        <h1 style={s.title}>Security Dashboard</h1>
        <p style={s.subtitle}>Monitor phishing simulations, track delivery stages, and identify risky users</p>
      </div>

      {/* ── KPI Stats ───────────────────────────────────────── */}
      <div style={s.statsRow}>
        <StatCard label="Total Campaigns" value={overview?.total_campaigns ?? 0} accentColor="#6366f1" sub={`${overview?.active_campaigns ?? 0} active`} subColor="#818cf8" />
        <StatCard label="Targets Enrolled" value={overview?.total_targets ?? 0} accentColor="#0ea5e9" sub="across all campaigns" subColor="#38bdf8" />
        <StatCard label="Open Rate" value={`${overview?.overall_open_rate ?? 0}%`} accentColor="#f59e0b" sub="email opened" subColor="#fbbf24" />
        <StatCard label="Click Rate" value={`${overview?.overall_click_rate ?? 0}%`} accentColor="#ef4444" sub="phishing link clicked" subColor="#f87171" />
        <StatCard label="Submission Rate" value={`${overview?.overall_submission_rate ?? 0}%`} accentColor="#dc2626" sub="credentials submitted" subColor="#fb923c" />
      </div>

      {/* ── Funnel + Risky Users ─────────────────────────────── */}
      <div style={s.grid2}>
        <div style={s.card}>
          <div style={s.row}>
            <span style={s.cardTitle}>📬 Email Delivery Funnel</span>
            <select
              style={s.select}
              value={selectedCampaign}
              onChange={e => setSelectedCampaign(e.target.value)}
            >
              <option value="">Select campaign…</option>
              {campaigns.map(c => (
                <option key={c.id} value={String(c.id)}>{c.name}</option>
              ))}
            </select>
          </div>
          {selectedCampaign
            ? <FunnelChart campaignId={selectedCampaign} />
            : <p style={{ color: '#64748b', fontSize: 13 }}>Select a campaign to view its funnel</p>}
        </div>

        <div style={s.card}>
          <span style={s.cardTitle}>⚠️ Risky Users Leaderboard</span>
          <RiskyUsers />
        </div>
      </div>

      {/* ── Trend Chart ──────────────────────────────────────── */}
      <div style={s.card}>
        <span style={s.cardTitle}>📈 Campaign Performance Trends</span>
        <TrendChart />
      </div>

      {/* ── Department Heatmap ────────────────────────────────── */}
      <div style={s.card}>
        <span style={s.cardTitle}>🏢 Department Vulnerability Heatmap</span>
        <DepartmentHeatmap />
      </div>
    </div>
  )
}
