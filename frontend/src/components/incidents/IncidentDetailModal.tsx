import { useState, useEffect } from 'react'
import { X, AlertTriangle, CheckCircle, TrendingUp, Clock, Shield } from 'lucide-react'
import api from '@/lib/api'
import { SeverityBadge } from '../common/Badge'
import LoadingSpinner from '../common/LoadingSpinner'
import { toast } from 'react-hot-toast'
import { format } from 'date-fns'

interface IncidentDetailModalProps {
  incidentId: number
  onClose: () => void
  onUpdate: () => void
}

export default function IncidentDetailModal({
  incidentId,
  onClose,
  onUpdate,
}: IncidentDetailModalProps) {
  const [incident, setIncident] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [updating, setUpdating] = useState(false)

  useEffect(() => {
    fetchIncidentDetails()
  }, [incidentId])

  const fetchIncidentDetails = async () => {
    setLoading(true)
    try {
      const response = await api.get(`/incidents/${incidentId}`)
      setIncident(response.data)
    } catch (error) {
      toast.error('Failed to load incident details')
    } finally {
      setLoading(false)
    }
  }

  const handleEscalate = async () => {
    setUpdating(true)
    try {
      await api.post(`/incidents/${incidentId}/escalate`)
      toast.success('Incident escalated to CRITICAL')
      fetchIncidentDetails()
      onUpdate()
    } catch (error) {
      toast.error('Failed to escalate incident')
    } finally {
      setUpdating(false)
    }
  }

  const handleResolve = async () => {
    const summary = prompt('Enter resolution summary:')
    if (!summary) return

    setUpdating(true)
    try {
      await api.post(`/incidents/${incidentId}/resolve`, {
        resolution_summary: summary,
      })
      toast.success('Incident resolved')
      fetchIncidentDetails()
      onUpdate()
      onClose()
    } catch (error) {
      toast.error('Failed to resolve incident')
    } finally {
      setUpdating(false)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 90) return 'text-red-400'
    if (score >= 70) return 'text-orange-400'
    if (score >= 50) return 'text-yellow-400'
    return 'text-green-400'
  }

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-dark-300 rounded-lg p-12">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    )
  }

  if (!incident) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-dark-300 rounded-lg border border-dark-50 w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-dark-50">
          <div className="flex items-center gap-3">
            <Shield className="text-red-400" size={24} />
            <div>
              <h2 className="text-xl font-bold text-gray-100">Incident Investigation</h2>
              <p className="text-sm text-gray-500 mt-1">ID: {incident.incident_uuid}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-dark-400 rounded-lg transition-colors"
          >
            <X size={20} className="text-gray-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Overview */}
          <div>
            <h3 className="text-lg font-semibold text-gray-100 mb-4">Overview</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-dark-400 rounded-lg p-4">
                <p className="text-sm text-gray-400 mb-1">Severity</p>
                <SeverityBadge severity={incident.severity} />
              </div>
              <div className="bg-dark-400 rounded-lg p-4">
                <p className="text-sm text-gray-400 mb-1">Risk Score</p>
                <p className={`text-2xl font-bold ${getRiskColor(incident.risk_score)}`}>
                  {incident.risk_score}
                </p>
              </div>
              <div className="bg-dark-400 rounded-lg p-4">
                <p className="text-sm text-gray-400 mb-1">Status</p>
                <p className="text-gray-100 uppercase">{incident.status}</p>
              </div>
              <div className="bg-dark-400 rounded-lg p-4">
                <p className="text-sm text-gray-400 mb-1">Alerts</p>
                <p className="text-2xl font-bold text-gray-100">{incident.alert_count}</p>
              </div>
            </div>
          </div>

          {/* Incident Details */}
          <div>
            <h3 className="text-lg font-semibold text-gray-100 mb-2">Incident Details</h3>
            <div className="bg-dark-400 rounded-lg p-4">
              <h4 className="font-semibold text-gray-100 text-lg mb-2">{incident.title}</h4>
              {incident.description && <p className="text-gray-400">{incident.description}</p>}
            </div>
          </div>

          {/* Attack Chain */}
          {incident.attack_chain?.chain_detected && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">Attack Chain Detected</h3>
              <div className="bg-red-900/20 border border-red-900/30 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="text-red-400 mt-1" size={20} />
                  <div className="flex-1">
                    <p className="font-semibold text-red-300 mb-2">
                      {incident.attack_chain.chain_name}
                    </p>
                    <p className="text-sm text-red-200 mb-3">
                      {incident.attack_chain.chain_description}
                    </p>
                    {incident.attack_chain.stages && (
                      <div className="flex items-center gap-2 flex-wrap">
                        {incident.attack_chain.stages.map((stage: string, index: number) => (
                          <div key={index}>
                            <span className="badge bg-red-900/50 text-red-200">{stage}</span>
                            {index < incident.attack_chain.stages.length - 1 && (
                              <span className="text-red-400 mx-2">→</span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Timeline */}
          {incident.timeline && incident.timeline.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">Timeline</h3>
              <div className="space-y-3">
                {incident.timeline.map((event: any, index: number) => (
                  <div
                    key={index}
                    className="flex gap-4 p-3 bg-dark-400 rounded-lg border border-dark-50"
                  >
                    <div className="flex flex-col items-center">
                      <Clock className="text-gray-500" size={16} />
                      <div className="w-px bg-dark-50 flex-1 my-2" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={event.severity} />
                        <p className="text-xs text-gray-500">
                          {format(new Date(event.timestamp), 'PPpp')}
                        </p>
                      </div>
                      <p className="font-medium text-gray-100">{event.event}</p>
                      {event.description && (
                        <p className="text-sm text-gray-400 mt-1">{event.description}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Related Alerts */}
          {incident.alerts && incident.alerts.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">
                Related Alerts ({incident.alerts.length})
              </h3>
              <div className="space-y-2">
                {incident.alerts.slice(0, 5).map((alert: any) => (
                  <div key={alert.id} className="p-3 bg-dark-400 rounded-lg border border-dark-50">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={alert.severity} />
                        <div>
                          <p className="text-sm font-medium text-gray-100">{alert.title}</p>
                          <p className="text-xs text-gray-500 mt-1">
                            {format(new Date(alert.timestamp), 'PPp')}
                          </p>
                        </div>
                      </div>
                      {alert.src_ip && (
                        <p className="text-sm font-mono text-gray-400">{alert.src_ip}</p>
                      )}
                    </div>
                  </div>
                ))}
                {incident.alerts.length > 5 && (
                  <p className="text-sm text-gray-500 text-center py-2">
                    + {incident.alerts.length - 5} more alerts
                  </p>
                )}
              </div>
            </div>
          )}

          {/* MITRE Techniques */}
          {incident.mitre_details && incident.mitre_details.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">MITRE ATT&CK Techniques</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {incident.mitre_details.map((technique: any) => (
                  <div key={technique.id} className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                    <p className="font-semibold text-gray-100">{technique.id}</p>
                    <p className="text-sm text-gray-400 mt-1">{technique.name}</p>
                    <p className="text-xs text-gray-500 mt-2">{technique.tactic}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-end gap-3 p-6 border-t border-dark-50">
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          {incident.status === 'open' && (
            <>
              <button
                onClick={handleEscalate}
                disabled={updating}
                className="btn btn-danger flex items-center gap-2"
              >
                <TrendingUp size={16} />
                Escalate
              </button>
              <button
                onClick={handleResolve}
                disabled={updating}
                className="btn btn-success flex items-center gap-2"
              >
                <CheckCircle size={16} />
                Resolve
              </button>
            </>
          )}
          {incident.status === 'investigating' && (
            <button
              onClick={handleResolve}
              disabled={updating}
              className="btn btn-success flex items-center gap-2"
            >
              <CheckCircle size={16} />
              Resolve
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
