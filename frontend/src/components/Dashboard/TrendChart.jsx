import { useState, useEffect } from 'react'
import { getTrends } from '../../api'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer, ReferenceLine
} from 'recharts'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e2232', border: '1px solid #374151',
      borderRadius: 10, padding: '10px 14px', fontSize: 13, color: '#e2e8f0'
    }}>
      <div style={{ fontWeight: 600, marginBottom: 6, color: '#f1f5f9' }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.color, display: 'flex', gap: 8, marginBottom: 2 }}>
          <span>{p.name}:</span>
          <strong>{p.value}%</strong>
        </div>
      ))}
    </div>
  )
}

export default function TrendChart() {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getTrends()
      .then(d => {
        setData(d.map(c => ({
          name: c.campaign_name.length > 16 ? c.campaign_name.slice(0, 14) + '…' : c.campaign_name,
          fullName: c.campaign_name,
          'Open Rate': c.open_rate,
          'Click Rate': c.click_rate,
          'Submit Rate': c.submission_rate,
          targets: c.total_targets,
        })))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ color: '#64748b', padding: 20, textAlign: 'center' }}>Loading trends…</div>
  if (!data.length) return (
    <div style={{ color: '#64748b', padding: 20, textAlign: 'center', fontSize: 13 }}>
      No campaign trend data yet. Launch campaigns to see trends.
    </div>
  )

  return (
    <div>
      <div style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>
        Rate progression across {data.length} campaign{data.length !== 1 ? 's' : ''}
      </div>
      <ResponsiveContainer width="100%" height={280}>
        <LineChart data={data} margin={{ top: 10, right: 20, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2232" />
          <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={false} tickLine={false}
            tickFormatter={v => `${v}%`}
            domain={[0, 100]}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend
            wrapperStyle={{ paddingTop: 16, fontSize: 12, color: '#94a3b8' }}
          />
          <ReferenceLine y={20} stroke="#374151" strokeDasharray="4 4" />
          <Line
            type="monotone" dataKey="Open Rate" stroke="#f59e0b"
            strokeWidth={2.5} dot={{ fill: '#f59e0b', r: 4 }} activeDot={{ r: 6 }}
          />
          <Line
            type="monotone" dataKey="Click Rate" stroke="#ef4444"
            strokeWidth={2.5} dot={{ fill: '#ef4444', r: 4 }} activeDot={{ r: 6 }}
          />
          <Line
            type="monotone" dataKey="Submit Rate" stroke="#dc2626"
            strokeWidth={2.5} dot={{ fill: '#dc2626', r: 4 }} activeDot={{ r: 6 }}
            strokeDasharray="5 3"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
