import { useState } from 'react'
import { X, ExternalLink, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { Alert } from '@/types'
import { SeverityBadge, StatusBadge } from '../common/Badge'
import api from '@/lib/api'
import { toast } from 'react-hot-toast'
import { format } from 'date-fns'

interface AlertDetailModalProps {
  alert: Alert
  onClose: () => void
  onUpdate: () => void
}

export default function AlertDetailModal({ alert, onClose, onUpdate }: AlertDetailModalProps) {
  const [updating, setUpdating] = useState(false)
  const [notes, setNotes] = useState('')

  const handleStatusChange = async (newStatus: string) => {
    setUpdating(true)
    try {
      await api.patch(`/alerts/${alert.id}`, {
        status: newStatus,
        resolution_notes: notes || undefined,
      })
      toast.success('Alert updated')
      onUpdate()
      onClose()
    } catch (error) {
      toast.error('Failed to update alert')
    } finally {
      setUpdating(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-dark-300 rounded-lg border border-dark-50 w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-dark-50">
          <div className="flex items-center gap-3">
            <AlertTriangle className="text-orange-400" size={24} />
            <div>
              <h2 className="text-xl font-bold text-gray-100">Alert Details</h2>
              <p className="text-sm text-gray-500 mt-1">ID: {alert.alert_uuid}</p>
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
          {/* Basic Info */}
          <div>
            <h3 className="text-lg font-semibold text-gray-100 mb-4">Overview</h3>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-400 mb-1">Severity</p>
                <SeverityBadge severity={alert.severity} />
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Status</p>
                <StatusBadge status={alert.status} />
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Confidence</p>
                <p className="text-gray-100">{alert.confidence}%</p>
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Timestamp</p>
                <p className="text-gray-100">
                  {format(new Date(alert.timestamp), 'PPpp')}
                </p>
              </div>
            </div>
          </div>

          {/* Alert Details */}
          <div>
            <h3 className="text-lg font-semibold text-gray-100 mb-2">Alert Information</h3>
            <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
              <h4 className="font-semibold text-gray-100 mb-2">{alert.title}</h4>
              {alert.description && (
                <p className="text-gray-400 text-sm">{alert.description}</p>
              )}
            </div>
          </div>

          {/* Network Info */}
          <div>
            <h3 className="text-lg font-semibold text-gray-100 mb-4">Network Details</h3>
            <div className="grid grid-cols-2 gap-4">
              {alert.src_ip && (
                <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                  <p className="text-sm text-gray-400 mb-1">Source</p>
                  <p className="font-mono text-gray-100">
                    {alert.src_ip}
                    {alert.src_port && `:${alert.src_port}`}
                  </p>
                </div>
              )}
              {alert.dst_ip && (
                <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                  <p className="text-sm text-gray-400 mb-1">Destination</p>
                  <p className="font-mono text-gray-100">
                    {alert.dst_ip}
                    {alert.dst_port && `:${alert.dst_port}`}
                  </p>
                </div>
              )}
              {alert.protocol && (
                <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                  <p className="text-sm text-gray-400 mb-1">Protocol</p>
                  <p className="text-gray-100">{alert.protocol}</p>
                </div>
              )}
              {alert.category && (
                <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                  <p className="text-sm text-gray-400 mb-1">Category</p>
                  <p className="text-gray-100 uppercase">{alert.category}</p>
                </div>
              )}
            </div>
          </div>

          {/* Evidence */}
          {alert.evidence && Object.keys(alert.evidence).length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">Evidence</h3>
              <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                <pre className="text-xs text-gray-300 overflow-x-auto">
                  {JSON.stringify(alert.evidence, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* MITRE ATT&CK */}
          {alert.mitre_attack_id && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-4">MITRE ATT&CK</h3>
              <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-gray-100">{alert.mitre_attack_id}</p>
                    <p className="text-sm text-gray-400 mt-1">
                      View technique details on MITRE ATT&CK framework
                    </p>
                  </div>
                  <a
                    href={`https://attack.mitre.org/techniques/${alert.mitre_attack_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-secondary flex items-center gap-2"
                  >
                    <ExternalLink size={16} />
                    View
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* Resolution Notes */}
          {alert.status !== 'new' && (
            <div>
              <h3 className="text-lg font-semibold text-gray-100 mb-2">Resolution Notes</h3>
              <div className="bg-dark-400 rounded-lg p-4 border border-dark-50">
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Add resolution notes..."
                  className="input w-full h-24 resize-none"
                />
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-end gap-3 p-6 border-t border-dark-50">
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
          {alert.status === 'new' && (
            <>
              <button
                onClick={() => handleStatusChange('acknowledged')}
                disabled={updating}
                className="btn btn-secondary flex items-center gap-2"
              >
                <CheckCircle size={16} />
                Acknowledge
              </button>
              <button
                onClick={() => handleStatusChange('investigating')}
                disabled={updating}
                className="btn btn-primary flex items-center gap-2"
              >
                <AlertTriangle size={16} />
                Investigate
              </button>
            </>
          )}
          {alert.status === 'investigating' && (
            <button
              onClick={() => handleStatusChange('resolved')}
              disabled={updating}
              className="btn btn-success flex items-center gap-2"
            >
              <CheckCircle size={16} />
              Resolve
            </button>
          )}
          <button
            onClick={() => handleStatusChange('false_positive')}
            disabled={updating}
            className="btn btn-secondary flex items-center gap-2"
          >
            <XCircle size={16} />
            False Positive
          </button>
        </div>
      </div>
    </div>
  )
}
