import { Bell, LogOut, User } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'

export default function Header() {
  const { user, logout } = useAuthStore()

  return (
    <header className="bg-dark-400 border-b border-dark-50 px-6 py-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-100">Welcome back, {user?.username}</h2>
          <p className="text-sm text-gray-500">Monitor your network security in real-time</p>
        </div>

        <div className="flex items-center gap-4">
          {/* Notifications */}
          <button className="relative p-2 hover:bg-dark-300 rounded-lg transition-colors">
            <Bell size={20} className="text-gray-400" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-danger rounded-full" />
          </button>

          {/* User Menu */}
          <div className="flex items-center gap-3 px-3 py-2 bg-dark-300 rounded-lg">
            <div className="p-2 bg-primary-900/30 rounded-full">
              <User size={16} className="text-primary-400" />
            </div>
            <div className="text-sm">
              <p className="font-medium text-gray-100">{user?.username}</p>
              <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
            </div>
          </div>

          {/* Logout */}
          <button
            onClick={logout}
            className="p-2 hover:bg-dark-300 rounded-lg transition-colors text-gray-400 hover:text-danger"
            title="Logout"
          >
            <LogOut size={20} />
          </button>
        </div>
      </div>
    </header>
  )
}
