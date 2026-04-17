import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Layout/Navbar'
import Dashboard from './components/Dashboard/Dashboard'
import CampaignList from './components/Campaigns/CampaignList'
import CampaignCreate from './components/Campaigns/CampaignCreate'
import CampaignDetail from './components/Campaigns/CampaignDetail'

const styles = {
  layout: {
    display: 'flex',
    flexDirection: 'column',
    minHeight: '100vh',
  },
  main: {
    flex: 1,
    padding: '28px 32px',
    maxWidth: 1400,
    margin: '0 auto',
    width: '100%',
  }
}

export default function App() {
  return (
    <BrowserRouter>
      <div style={styles.layout}>
        <Navbar />
        <main style={styles.main}>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/campaigns" element={<CampaignList />} />
            <Route path="/campaigns/new" element={<CampaignCreate />} />
            <Route path="/campaigns/:id" element={<CampaignDetail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
