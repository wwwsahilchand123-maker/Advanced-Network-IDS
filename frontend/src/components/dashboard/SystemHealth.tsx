import { Server, Database, Radio, CheckCircle, XCircle, AlertCircle } from 'lucide-react'
import Card from '../common/Card'

interface HealthStatus {
  capture_engine: string
  detection_engine: string
  database: string
  overall_status: string
}

interface SystemHealthProps {
  status: HealthStatus
  loading?: boolean
}

export default function SystemHealth({ status, loading = false }: SystemHealthProps) {
  const getStatusIcon = (state: string) => {
    if (state === 'running' || state === 'healthy') {
      return <CheckCircle className="text-success" size={20} />
    } else if (state === 'degraded') {
      return <AlertCircle className="text-warning" size={20} />
    } else {
      return <XCircle className="text-danger" size={20} />
    }
  }

  const getStatusText = (state: string) => {
    const status: Record<string, { text: string; color: string }> = {
      running: { text: 'Running', color: 'text-success' },
      healthy: { text: 'Healthy', color: 'text-success' },
      stopped: { text: 'Stopped', color: 'text-gray-400' },
      error: { text: 'Error', color: 'text-danger' },
      degraded: { text: 'Degraded', color: 'text-warning' },
    }
    return status[state] || { text: state, color: 'text-gray-400' }
  }

  if (loading) {
    return (
      <Card title="System Health">
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-12 bg-dark-400 animate-pulse rounded" />
          ))}
        </div>
      </Card>
    )
  }

  const services = [
    { name: 'Capture Engine', icon: Radio, status: status.capture_engine },
    { name: 'Detection Engine', icon: Server, status: status.detection_engine },
    { name: 'Database', icon: Database, status: status.database },
  ]

  return (
    <Card title="System Health">
      <div className="space-y-3">
        {services.map((service) => {
          const statusInfo = getStatusText(service.status)
          return (
            <div
              key={service.name}
              className="flex items-center justify-between p-3 rounded-lg bg-dark-400 border border-dark-50"
            >
              <div className="flex items-center gap-3">
                <service.icon className="text-gray-400" size={20} />
                <span className="text-gray-100">{service.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {getStatusIcon(service.status)}
                <span className={`font-medium ${statusInfo.color}`}>{statusInfo.text}</span>
              </div>
            </div>
          )
        })}
        
        <div className="mt-4 p-3 rounded-lg bg-dark-500 border border-dark-50">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-gray-100">Overall Status</span>
            <div className="flex items-center gap-2">
              {getStatusIcon(status.overall_status)}
              <span className={`font-bold ${getStatusText(status.overall_status).color}`}>
                {getStatusText(status.overall_status).text.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
