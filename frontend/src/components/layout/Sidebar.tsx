import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  AlertTriangle,
  FileWarning,
  Shield,
  Settings,
  Activity,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'Incidents', href: '/incidents', icon: FileWarning },
  { name: 'Network', href: '/network', icon: Activity },
  { name: 'Rules', href: '/rules', icon: Shield },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function Sidebar() {
  const location = useLocation()

  return (
    <div className="flex flex-col w-64 bg-dark-400 border-r border-dark-50">
      {/* Logo */}
      <div className="flex items-center gap-3 p-6 border-b border-dark-50">
        <div className="p-2 bg-primary-900/30 rounded-lg">
          <Shield className="text-primary-500" size={24} />
        </div>
        <div>
          <h1 className="text-xl font-bold text-gray-100">Advanced IDS</h1>
          <p className="text-xs text-gray-500">Network Security</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1">
        {navigation.map((item) => {
          const isActive = location.pathname === item.href
          return (
            <Link
              key={item.name}
              to={item.href}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive
                  ? 'bg-primary-900/30 text-primary-400'
                  : 'text-gray-400 hover:bg-dark-300 hover:text-gray-200'
              }`}
            >
              <item.icon size={20} />
              <span className="font-medium">{item.name}</span>
            </Link>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-dark-50">
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <div className="live-indicator" />
          <span>System Active</span>
        </div>
      </div>
    </div>
  )
}
