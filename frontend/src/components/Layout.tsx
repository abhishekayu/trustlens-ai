import { Outlet, Link, useLocation } from 'react-router-dom'
import { Shield, Search, Users, Info } from 'lucide-react'

const navItems = [
  { path: '/', label: 'Scan', icon: Search },
  { path: '/community', label: 'Community', icon: Users },
  { path: '/about', label: 'About', icon: Info },
]

export default function Layout() {
  const { pathname } = useLocation()

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 rounded-lg bg-sky-500/15 flex items-center justify-center group-hover:bg-sky-500/25 transition">
              <Shield className="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <span className="font-bold text-lg text-white tracking-tight">TrustLens</span>
              <span className="text-sky-400 font-semibold text-xs ml-1">AI</span>
            </div>
          </Link>

          <nav className="flex items-center gap-1">
            {navItems.map(({ path, label, icon: Icon }) => {
              const active = pathname === path
              return (
                <Link
                  key={path}
                  to={path}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition ${
                    active
                      ? 'text-sky-400 bg-sky-500/10'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </Link>
              )
            })}
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 py-6">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-500">
          <p>TrustLens AI &mdash; AI advises. Rules decide. Evidence explains.</p>
          <div className="flex items-center gap-4">
            <a href="https://github.com/abhishekayu/TrustLens" target="_blank" rel="noreferrer" className="hover:text-gray-300 transition">GitHub</a>
            <a href="/api/v1/docs" target="_blank" rel="noreferrer" className="hover:text-gray-300 transition">API Docs</a>
            <span>MIT License</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
