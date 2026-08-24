import { ArrowUpRight, Activity } from 'lucide-react'
import Card from '../common/Card'
import { TopHost } from '@/types'

interface TopHostsProps {
  title: string
  hosts: TopHost[]
  loading?: boolean
}

export default function TopHosts({ title, hosts, loading = false }: TopHostsProps) {
  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const getRiskColor = (score?: number) => {
    if (!score) return 'text-gray-500'
    if (score >= 70) return 'text-red-400'
    if (score >= 40) return 'text-orange-400'
    if (score >= 20) return 'text-yellow-400'
    return 'text-green-400'
  }

  if (loading) {
    return (
      <Card title={title}>
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-dark-400 animate-pulse rounded" />
          ))}
        </div>
      </Card>
    )
  }

  return (
    <Card title={title}>
      <div className="space-y-3">
        {hosts.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Activity className="mx-auto mb-2 opacity-50" size={32} />
            <p>No data available</p>
          </div>
        ) : (
          hosts.map((host, index) => (
            <div
              key={host.ip_address}
              className="p-3 rounded-lg bg-dark-400 hover:bg-dark-300 transition-colors border border-dark-50"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 flex-1">
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-primary-900/30 text-primary-400 font-semibold text-sm">
                    {index + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-mono font-medium text-gray-100">{host.ip_address}</p>
                    <div className="flex items-center gap-3 mt-1 text-xs text-gray-400">
                      {host.packets && (
                        <span>{host.packets.toLocaleString()} packets</span>
                      )}
                      {host.bytes && <span>{formatBytes(host.bytes)}</span>}
                      {host.alert_count !== undefined && host.alert_count > 0 && (
                        <span className="text-orange-400">{host.alert_count} alerts</span>
                      )}
                    </div>
                  </div>
                </div>
                {host.risk_score !== undefined && host.risk_score > 0 && (
                  <div className="flex items-center gap-1">
                    <ArrowUpRight size={14} className={getRiskColor(host.risk_score)} />
                    <span className={`font-semibold ${getRiskColor(host.risk_score)}`}>
                      {host.risk_score}
                    </span>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  )
}
