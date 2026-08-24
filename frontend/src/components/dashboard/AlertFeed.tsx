import { useEffect, useState } from 'react'
import { AlertTriangle, Clock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import Card from '../common/Card'
import { SeverityBadge } from '../common/Badge'
import { Alert } from '@/types'
import { wsClient } from '@/lib/websocket'

interface AlertFeedProps {
  initialAlerts: Alert[]
}

export default function AlertFeed({ initialAlerts }: AlertFeedProps) {
  const [alerts, setAlerts] = useState<Alert[]>(initialAlerts)

  useEffect(() => {
    // Listen for new alerts via WebSocket
    const handleNewAlert = (alert: Alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 10)) // Keep only last 10
    }

    wsClient.on('new_alert', handleNewAlert)

    return () => {
      wsClient.off('new_alert', handleNewAlert)
    }
  }, [])

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: 'text-red-400 bg-red-900/20',
      HIGH: 'text-orange-400 bg-orange-900/20',
      MEDIUM: 'text-yellow-400 bg-yellow-900/20',
      LOW: 'text-gray-400 bg-gray-900/20',
      INFO: 'text-blue-400 bg-blue-900/20',
    }
    return colors[severity] || colors.INFO
  }

  return (
    <Card
      title="Live Alert Feed"
      headerAction={
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <div className="live-indicator" />
          <span>Live</span>
        </div>
      }
    >
      <div className="space-y-3 max-h-96 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <AlertTriangle className="mx-auto mb-2 opacity-50" size={32} />
            <p>No recent alerts</p>
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className={`p-3 rounded-lg border border-dark-50 hover:bg-dark-400 transition-colors cursor-pointer ${getSeverityColor(
                alert.severity
              )}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={alert.severity} />
                    {alert.category && (
                      <span className="text-xs text-gray-500 uppercase">{alert.category}</span>
                    )}
                  </div>
                  <p className="font-medium text-sm text-gray-100 truncate">{alert.title}</p>
                  {alert.src_ip && (
                    <p className="text-xs text-gray-400 mt-1">
                      Source: {alert.src_ip}
                      {alert.dst_ip && ` → ${alert.dst_ip}`}
                      {alert.dst_port && `:${alert.dst_port}`}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-1 text-xs text-gray-500 whitespace-nowrap">
                  <Clock size={12} />
                  <span>
                    {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  )
}
