import { Settings as SettingsIcon, User, Shield, Database } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'

export default function Settings() {
  const { user, logout } = useAuthStore()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Settings</h1>
        <p className="text-gray-400 mt-1">System configuration and preferences</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Profile */}
        <div className="card card-body">
          <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
            <User className="text-primary-500" size={20} />
            User Profile
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Username</span>
              <span className="text-gray-200">{user?.username || 'N/A'}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Email</span>
              <span className="text-gray-200">{user?.email || 'N/A'}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Role</span>
              <span className="badge badge-info">{user?.role || 'N/A'}</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-gray-400">Status</span>
              <span className="text-success">Active</span>
            </div>
          </div>
          <button
            onClick={logout}
            className="btn btn-danger mt-4 w-full"
          >
            Sign Out
          </button>
        </div>

        {/* System Info */}
        <div className="card card-body">
          <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
            <SettingsIcon className="text-primary-500" size={20} />
            System Information
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Application</span>
              <span className="text-gray-200">Advanced IDS v1.0.0</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Environment</span>
              <span className="badge badge-medium">Development</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">API Endpoint</span>
              <span className="text-gray-200 font-mono text-xs">http://localhost:8000</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-gray-400">WebSocket</span>
              <span className="text-success">Connected</span>
            </div>
          </div>
        </div>

        {/* Security Settings */}
        <div className="card card-body">
          <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
            <Shield className="text-primary-500" size={20} />
            Security
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Token Expiry</span>
              <span className="text-gray-200">24 hours</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Algorithm</span>
              <span className="text-gray-200 font-mono">HS256</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-gray-400">Refresh Token</span>
              <span className="text-gray-200">7 days</span>
            </div>
          </div>
        </div>

        {/* Data Retention */}
        <div className="card card-body">
          <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
            <Database className="text-primary-500" size={20} />
            Data Retention
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Alert Retention</span>
              <span className="text-gray-200">90 days</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Incident Retention</span>
              <span className="text-gray-200">365 days</span>
            </div>
            <div className="flex justify-between py-2 border-b border-dark-50">
              <span className="text-gray-400">Packet Retention</span>
              <span className="text-gray-200">24 hours</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-gray-400">Flow Retention</span>
              <span className="text-gray-200">7 days</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
