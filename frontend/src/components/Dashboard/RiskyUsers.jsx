import { useState, useEffect } from 'react'
import { getRiskyUsers } from '../../api'

const RISK_COLOR = (score) => {
  if (score >= 15) return '#dc2626'
  if (score >= 8) return '#ef4444'
  if (score >= 4) return '#f59e0b'
  return '#6366f1'
}

const RISK_LABEL = (score) => {
  if (score >= 15) return 'Critical'
  if (score >= 8) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

export default function RiskyUsers() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getRiskyUsers().then(d => { setUsers(d); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ color: '#64748b', padding: 20, textAlign: 'center' }}>Loading…</div>
  if (!users.length) return (
    <div style={{ color: '#64748b', padding: 20, textAlign: 'center', fontSize: 13 }}>
      No risky users detected yet.<br />Launch a campaign and simulate events.
    </div>
  )

  const maxScore = users[0]?.risk_score || 1

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 340, overflowY: 'auto' }}>
      {users.slice(0, 10).map((user, i) => {
        const color = RISK_COLOR(user.risk_score)
        return (
          <div key={user.email} style={{
            display: 'flex', alignItems: 'center', gap: 12,
            background: '#0f1117', borderRadius: 10, padding: '10px 14px',
            border: `1px solid #1e2232`,
          }}>
            {/* Rank */}
            <div style={{
              width: 26, height: 26, borderRadius: '50%',
              background: i < 3 ? color : '#1e2232',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, color: i < 3 ? '#fff' : '#64748b',
              flexShrink: 0,
            }}>
              {i + 1}
            </div>

            {/* Info */}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {user.name}
              </div>
              <div style={{ fontSize: 11, color: '#64748b' }}>{user.email} · {user.department}</div>
              {/* Progress bar */}
              <div style={{ marginTop: 6, height: 4, background: '#1e2232', borderRadius: 4 }}>
                <div style={{
                  height: '100%', borderRadius: 4, background: color,
                  width: `${(user.risk_score / maxScore) * 100}%`,
                  transition: 'width 0.4s ease',
                }} />
              </div>
            </div>

            {/* Score + stats */}
            <div style={{ textAlign: 'right', flexShrink: 0 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color }}>
                {user.risk_score}
              </div>
              <div style={{ fontSize: 10, color, fontWeight: 600 }}>{RISK_LABEL(user.risk_score)}</div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                {user.opens}👁 {user.clicks}🖱 {user.submissions}🔐
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
