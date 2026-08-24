import { useState, useEffect } from 'react'
import { Filter, Search, RefreshCw } from 'lucide-react'
import api from '@/lib/api'
import { Alert, Severity, AlertStatus } from '@/types'
import { SeverityBadge, StatusBadge } from '@/components/common/Badge'
import Card from '@/components/common/Card'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import AlertDetailModal from '@/components/alerts/AlertDetailModal'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'react-hot-toast'
import { wsClient } from '@/lib/websocket'

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [showModal, setShowModal] = useState(false)

  // Filters
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'ALL'>('ALL')
  const [showFilters, setShowFilters] = useState(false)

  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const [itemsPerPage] = useState(20)

  // Fetch alerts
  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const params: any = {
        limit: 100,
        skip: 0,
      }

      if (severityFilter !== 'ALL') params.severity = severityFilter
      if (statusFilter !== 'ALL') params.status = statusFilter
      if (searchTerm) params.search = searchTerm

      const response = await api.get('/alerts/', { params })
      setAlerts(response.data)
    } catch (error) {
      toast.error('Failed to fetch alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [severityFilter, statusFilter])

  // WebSocket listener for new alerts
  useEffect(() => {
    const handleNewAlert = (alert: Alert) => {
      setAlerts((prev) => [alert, ...prev])
      toast.success(`New ${alert.severity} alert: ${alert.title}`, {
        duration: 3000,
      })
    }

    wsClient.on('new_alert', handleNewAlert)
    return () => wsClient.off('new_alert', handleNewAlert)
  }, [])

  // Filter alerts by search term
  const filteredAlerts = alerts.filter((alert) => {
    if (!searchTerm) return true
    const search = searchTerm.toLowerCase()
    return (
      alert.title.toLowerCase().includes(search) ||
      alert.description?.toLowerCase().includes(search) ||
      alert.src_ip?.toLowerCase().includes(search) ||
      alert.dst_ip?.toLowerCase().includes(search)
    )
  })

  // Paginate
  const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage)
  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  const handleAlertClick = (alert: Alert) => {
    setSelectedAlert(alert)
    setShowModal(true)
  }

  const handleAcknowledge = async (alertId: number) => {
    try {
      await api.post(`/alerts/${alertId}/acknowledge`)
      toast.success('Alert acknowledged')
      fetchAlerts()
    } catch (error) {
      toast.error('Failed to acknowledge alert')
    }
  }

  const handleMarkFalsePositive = async (alertId: number) => {
    try {
      await api.post(`/alerts/${alertId}/false-positive`)
      toast.success('Marked as false positive')
      fetchAlerts()
    } catch (error) {
      toast.error('Failed to mark as false positive')
    }
  }

  // Stats
  const stats = {
    total: alerts.length,
    new: alerts.filter((a) => a.status === 'new').length,
    critical: alerts.filter((a) => a.severity === 'CRITICAL').length,
    high: alerts.filter((a) => a.severity === 'HIGH').length,
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Security Alerts</h1>
          <p className="text-gray-400 mt-1">Manage and investigate security events</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`btn ${showFilters ? 'btn-primary' : 'btn-secondary'} flex items-center gap-2`}
          >
            <Filter size={18} />
            Filters
          </button>
          <button onClick={fetchAlerts} className="btn btn-secondary flex items-center gap-2">
            <RefreshCw size={18} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">Total Alerts</p>
            <p className="text-3xl font-bold text-gray-100 mt-1">{stats.total}</p>
          </div>
        </Card>
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">New</p>
            <p className="text-3xl font-bold text-blue-400 mt-1">{stats.new}</p>
          </div>
        </Card>
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">Critical</p>
            <p className="text-3xl font-bold text-red-400 mt-1">{stats.critical}</p>
          </div>
        </Card>
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">High Severity</p>
            <p className="text-3xl font-bold text-orange-400 mt-1">{stats.high}</p>
          </div>
        </Card>
      </div>

      {/* Filters */}
      {showFilters && (
        <Card>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Severity</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as Severity | 'ALL')}
                className="input"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFO">Info</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as AlertStatus | 'ALL')}
                className="input"
              >
                <option value="ALL">All Statuses</option>
                <option value="new">New</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Search</label>
              <div className="relative">
                <Search
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                  size={18}
                />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search alerts..."
                  className="input pl-10"
                />
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Alerts Table */}
      <Card>
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        ) : paginatedAlerts.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <p>No alerts found</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-dark-50">
                  <tr>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Severity
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Alert
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Source
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Destination
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Time
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Status
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-gray-300">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-50">
                  {paginatedAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => handleAlertClick(alert)}
                      className="hover:bg-dark-400 transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-4">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <div>
                          <p className="font-medium text-gray-100">{alert.title}</p>
                          {alert.category && (
                            <p className="text-xs text-gray-500 mt-1 uppercase">{alert.category}</p>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <p className="font-mono text-sm text-gray-300">
                          {alert.src_ip || '-'}
                          {alert.src_port && `:${alert.src_port}`}
                        </p>
                      </td>
                      <td className="py-3 px-4">
                        <p className="font-mono text-sm text-gray-300">
                          {alert.dst_ip || '-'}
                          {alert.dst_port && `:${alert.dst_port}`}
                        </p>
                      </td>
                      <td className="py-3 px-4 text-sm text-gray-400">
                        {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                          {alert.status === 'new' && (
                            <button
                              onClick={() => handleAcknowledge(alert.id)}
                              className="text-xs px-2 py-1 bg-yellow-900/30 text-yellow-400 rounded hover:bg-yellow-900/50"
                            >
                              Acknowledge
                            </button>
                          )}
                          <button
                            onClick={() => handleMarkFalsePositive(alert.id)}
                            className="text-xs px-2 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
                          >
                            False+
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-dark-50">
                <p className="text-sm text-gray-400">
                  Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
                  {Math.min(currentPage * itemsPerPage, filteredAlerts.length)} of{' '}
                  {filteredAlerts.length} alerts
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="btn btn-secondary text-sm disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <span className="text-sm text-gray-400">
                    Page {currentPage} of {totalPages}
                  </span>
                  <button
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    className="btn btn-secondary text-sm disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      {/* Alert Detail Modal */}
      {showModal && selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => {
            setShowModal(false)
            setSelectedAlert(null)
          }}
          onUpdate={fetchAlerts}
        />
      )}
    </div>
  )
}
