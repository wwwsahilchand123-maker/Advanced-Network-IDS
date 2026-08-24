import { useState, useEffect } from 'react'
import { Filter, Search, RefreshCw, TrendingUp } from 'lucide-react'
import api from '@/lib/api'
import { Incident, Severity, IncidentStatus } from '@/types'
import { SeverityBadge } from '@/components/common/Badge'
import Card from '@/components/common/Card'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import IncidentDetailModal from '@/components/incidents/IncidentDetailModal'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'react-hot-toast'
import { wsClient } from '@/lib/websocket'

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [showModal, setShowModal] = useState(false)

  // Filters
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL')
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | 'ALL'>('ALL')
  const [showFilters, setShowFilters] = useState(false)

  const fetchIncidents = async () => {
    setLoading(true)
    try {
      const params: any = { limit: 100 }
      if (severityFilter !== 'ALL') params.severity = severityFilter
      if (statusFilter !== 'ALL') params.status = statusFilter

      const response = await api.get('/incidents/', { params })
      setIncidents(response.data)
    } catch (error) {
      toast.error('Failed to fetch incidents')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
  }, [severityFilter, statusFilter])

  // WebSocket listener
  useEffect(() => {
    const handleIncidentUpdate = (data: any) => {
      if (data.action === 'created') {
        setIncidents((prev) => [data.incident, ...prev])
        toast.error(`New incident: ${data.incident.title}`, { duration: 5000 })
      } else if (data.action === 'updated' || data.action === 'escalated') {
        fetchIncidents()
      }
    }

    wsClient.on('incident_update', handleIncidentUpdate)
    return () => wsClient.off('incident_update', handleIncidentUpdate)
  }, [])

  const filteredIncidents = incidents.filter((incident) => {
    if (!searchTerm) return true
    const search = searchTerm.toLowerCase()
    return (
      incident.title.toLowerCase().includes(search) ||
      incident.description?.toLowerCase().includes(search) ||
      incident.src_ip?.toLowerCase().includes(search)
    )
  })

  const handleIncidentClick = (incident: Incident) => {
    setSelectedIncident(incident)
    setShowModal(true)
  }

  const getRiskColor = (score: number) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-orange-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getStatusColor = (status: IncidentStatus) => {
    const colors: Record<IncidentStatus, string> = {
      open: 'bg-blue-900/30 text-blue-400',
      investigating: 'bg-yellow-900/30 text-yellow-400',
      contained: 'bg-orange-900/30 text-orange-400',
      resolved: 'bg-green-900/30 text-green-400',
    }
    return colors[status] || colors.open
  }

  const stats = {
    total: incidents.length,
    open: incidents.filter((i) => i.status === 'open').length,
    critical: incidents.filter((i) => i.severity === 'CRITICAL').length,
    avgRisk:
      incidents.length > 0
        ? Math.round(incidents.reduce((sum, i) => sum + i.risk_score, 0) / incidents.length)
        : 0,
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Security Incidents</h1>
          <p className="text-gray-400 mt-1">Correlated security events requiring investigation</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`btn ${showFilters ? 'btn-primary' : 'btn-secondary'} flex items-center gap-2`}
          >
            <Filter size={18} />
            Filters
          </button>
          <button onClick={fetchIncidents} className="btn btn-secondary flex items-center gap-2">
            <RefreshCw size={18} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">Total Incidents</p>
            <p className="text-3xl font-bold text-gray-100 mt-1">{stats.total}</p>
          </div>
        </Card>
        <Card className="bg-dark-400">
          <div className="text-center">
            <p className="text-sm text-gray-400">Open</p>
            <p className="text-3xl font-bold text-blue-400 mt-1">{stats.open}</p>
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
            <p className="text-sm text-gray-400">Avg Risk Score</p>
            <p className={`text-3xl font-bold mt-1 ${getRiskColor(stats.avgRisk)}`}>
              {stats.avgRisk}
            </p>
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
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Status</label>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as IncidentStatus | 'ALL')}
                className="input"
              >
                <option value="ALL">All Statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="resolved">Resolved</option>
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
                  placeholder="Search incidents..."
                  className="input pl-10"
                />
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Incidents List */}
      <Card>
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <p>No incidents found</p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredIncidents.map((incident) => (
              <div
                key={incident.id}
                onClick={() => handleIncidentClick(incident)}
                className="p-4 rounded-lg border border-dark-50 hover:bg-dark-400 transition-colors cursor-pointer"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <SeverityBadge severity={incident.severity} />
                      <span className={`badge ${getStatusColor(incident.status)}`}>
                        {incident.status.toUpperCase()}
                      </span>
                      <div className="flex items-center gap-1">
                        <TrendingUp size={14} className={getRiskColor(incident.risk_score)} />
                        <span className={`font-semibold ${getRiskColor(incident.risk_score)}`}>
                          Risk: {incident.risk_score}
                        </span>
                      </div>
                    </div>
                    <h3 className="font-semibold text-gray-100 mb-1">{incident.title}</h3>
                    {incident.description && (
                      <p className="text-sm text-gray-400 mb-2">{incident.description}</p>
                    )}
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      {incident.src_ip && <span>Source: {incident.src_ip}</span>}
                      <span>{incident.alert_count} alerts</span>
                      <span>{incident.affected_hosts} hosts</span>
                      <span>
                        {formatDistanceToNow(new Date(incident.first_seen), { addSuffix: true })}
                      </span>
                    </div>
                  </div>
                  {incident.attack_chain?.chain_detected && (
                    <div className="px-3 py-2 bg-red-900/20 border border-red-900/30 rounded-lg">
                      <p className="text-xs text-red-400 font-semibold">ATTACK CHAIN</p>
                      <p className="text-xs text-red-300 mt-1">
                        {incident.attack_chain.chain_name}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Incident Detail Modal */}
      {showModal && selectedIncident && (
        <IncidentDetailModal
          incidentId={selectedIncident.id}
          onClose={() => {
            setShowModal(false)
            setSelectedIncident(null)
          }}
          onUpdate={fetchIncidents}
        />
      )}
    </div>
  )
}
