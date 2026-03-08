import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import ScanPage from './pages/ScanPage'
import ResultsPage from './pages/ResultsPage'
import CommunityPage from './pages/CommunityPage'
import AboutPage from './pages/AboutPage'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<ScanPage />} />
        <Route path="/results/:id" element={<ResultsPage />} />
        <Route path="/community" element={<CommunityPage />} />
        <Route path="/about" element={<AboutPage />} />
      </Route>
    </Routes>
  )
}
