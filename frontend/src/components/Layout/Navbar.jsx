import { NavLink } from 'react-router-dom'

const s = {
  nav: {
    background: '#141720',
    borderBottom: '1px solid #1e2232',
    padding: '0 32px',
    display: 'flex',
    alignItems: 'center',
    height: 60,
    gap: 8,
    position: 'sticky',
    top: 0,
    zIndex: 100,
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginRight: 32,
    color: '#fff',
    fontWeight: 700,
    fontSize: 16,
  },
  icon: {
    width: 32,
    height: 32,
    background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
    borderRadius: 8,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: 16,
  },
  link: (active) => ({
    padding: '6px 14px',
    borderRadius: 8,
    fontSize: 14,
    fontWeight: 500,
    color: active ? '#fff' : '#94a3b8',
    background: active ? '#1e2232' : 'transparent',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    gap: 6,
  }),
  badge: {
    marginLeft: 'auto',
    fontSize: 12,
    color: '#64748b',
    fontWeight: 500,
  }
}

export default function Navbar() {
  return (
    <nav style={s.nav}>
      <div style={s.brand}>
        <div style={s.icon}>🎣</div>
        PhishSim
      </div>

      <NavLink to="/dashboard" style={({ isActive }) => s.link(isActive)}>
        📊 Dashboard
      </NavLink>
      <NavLink to="/campaigns" style={({ isActive }) => s.link(isActive)}>
        📧 Campaigns
      </NavLink>

      <span style={s.badge}>Security Awareness Platform</span>
    </nav>
  )
}
