import { useState, useEffect } from 'react'
import { getDepartments } from '../../api'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, Legend
} from 'recharts'

const RISK_BG = (rate) => {
  if (rate >= 30) return 'rgba(220, 38, 38, 0.15)'
  if (rate >= 15) return 'rgba(239, 68, 68, 0.12)'
  if (rate >= 5)  return 'rgba(245, 158, 11, 0.12)'
  return 'rgba(99, 102, 241, 0.08)'
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1e2232', border: '1px solid #374151', borderRadius: 10,
      padding: '10px 14px', fontSize: 13, color: '#e2e8f0'
    }}>
      <div style={{ fontWeight: 600, marginBottom: 6 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color, marginBottom: 2 }}>
          {p.name}: <strong>{p.value}%</strong>
        </div>
      ))}
    </div>
  )
}

export default function DepartmentHeatmap() {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getDepartments()
      .then(d => {
        setData(d.map(dep => ({
          ...dep,
          name: dep.department,
          'Click Rate': dep.click_rate,
          'Submit Rate': dep.submission_rate,
        })))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ color: '#64748b', padding: 20, textAlign: 'center' }}>Loading…</div>
  if (!data.length) return (
    <div style={{ color: '#64748b', padding: 20, textAlign: 'center', fontSize: 13 }}>
      No department data yet. Add targets with departments to see this view.
    </div>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Bar Chart */}
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} margin={{ top: 10, right: 20, left: -10, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2232" vertical={false} />
          <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis
            tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false}
            tickFormatter={v => `${v}%`} domain={[0, 100]}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
          <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8', paddingTop: 10 }} />
          <Bar dataKey="Click Rate" fill="#ef4444" radius={[4, 4, 0, 0]} maxBarSize={40} />
          <Bar dataKey="Submit Rate" fill="#dc2626" radius={[4, 4, 0, 0]} maxBarSize={40} />
        </BarChart>
      </ResponsiveContainer>

      {/* Table / Card Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
        {data.map(dep => (
          <div key={dep.department} style={{
            background: RISK_BG(dep.click_rate),
            border: '1px solid #1e2232',
            borderRadius: 10,
            padding: '14px 16px',
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', marginBottom: 8 }}>
              🏢 {dep.department}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#64748b' }}>Sent</span>
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>{dep.sent}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#64748b' }}>Opened</span>
                <span style={{ color: '#f59e0b', fontWeight: 600 }}>{dep.opened}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#64748b' }}>Clicked</span>
                <span style={{ color: '#ef4444', fontWeight: 600 }}>{dep.clicked}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#64748b' }}>Submitted</span>
                <span style={{ color: '#dc2626', fontWeight: 600 }}>{dep.submitted}</span>
              </div>
              <div style={{ borderTop: '1px solid #1e2232', marginTop: 6, paddingTop: 6, display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                <span style={{ color: '#64748b' }}>Click Rate</span>
                <span style={{
                  fontWeight: 700,
                  color: dep.click_rate >= 20 ? '#ef4444' : dep.click_rate >= 10 ? '#f59e0b' : '#6366f1'
                }}>{dep.click_rate}%</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
