import { useState, useEffect } from 'react'
import { getFunnel } from '../../api'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  Cell, ResponsiveContainer, LabelList
} from 'recharts'

const STAGE_COLORS = {
  sent:      '#6366f1',
  delivered: '#0ea5e9',
  opened:    '#f59e0b',
  clicked:   '#ef4444',
  submitted: '#dc2626',
}

const STAGE_LABELS = {
  sent:      '📤 Sent',
  delivered: '📬 Delivered',
  opened:    '👁️ Opened',
  clicked:   '🖱️ Clicked',
  submitted: '🔐 Submitted',
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div style={{
      background: '#1e2232', border: '1px solid #374151', borderRadius: 10,
      padding: '10px 14px', fontSize: 13, color: '#e2e8f0'
    }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{STAGE_LABELS[d.stage] || d.stage}</div>
      <div>Count: <strong>{d.count}</strong></div>
      <div>Rate: <strong style={{ color: STAGE_COLORS[d.stage] }}>{d.percentage}%</strong></div>
    </div>
  )
}

export default function FunnelChart({ campaignId }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!campaignId) return
    setLoading(true)
    getFunnel(campaignId)
      .then(d => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [campaignId])

  if (loading) return <div style={{ color: '#64748b', padding: 20, textAlign: 'center' }}>Loading funnel…</div>
  if (!data) return <div style={{ color: '#64748b', padding: 20 }}>No data available</div>

  const chartData = data.stages.map(s => ({
    ...s,
    label: STAGE_LABELS[s.stage] || s.stage,
  }))

  return (
    <div>
      <div style={{ fontSize: 12, color: '#64748b', marginBottom: 12 }}>
        {data.campaign_name} — {data.total_targets} total targets
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={chartData} margin={{ top: 20, right: 10, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2232" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
          <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={60}>
            {chartData.map((entry) => (
              <Cell key={entry.stage} fill={STAGE_COLORS[entry.stage] || '#6366f1'} />
            ))}
            <LabelList dataKey="percentage" position="top" formatter={v => `${v}%`}
              style={{ fill: '#94a3b8', fontSize: 11 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Stage pills */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
        {chartData.map(s => (
          <div key={s.stage} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: '#0f1117', border: '1px solid #1e2232',
            borderRadius: 20, padding: '4px 10px', fontSize: 12,
          }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: STAGE_COLORS[s.stage] }} />
            <span style={{ color: '#94a3b8' }}>{s.stage}</span>
            <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
