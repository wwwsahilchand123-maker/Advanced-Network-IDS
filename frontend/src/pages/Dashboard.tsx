import { Activity, AlertTriangle, Shield, TrendingUp, Zap } from 'lucide-react'
import StatCard from '@/components/common/StatCard'
import TrafficChart from '@/components/dashboard/TrafficChart'
import ProtocolChart from '@/components/dashboard/ProtocolChart'
import AlertFeed from '@/components/dashboard/AlertFeed'
import TopHosts from '@/components/dashboard/TopHosts'
import SystemHealth from '@/components/dashboard/SystemHealth'
import { useDashboard } from '@/hooks/useDashboard'

export default function Dashboard() {
  const {
    stats,
    trafficData,
    protocolData,
    topSources,
    topDestinations,
    recentAlerts,
    systemHealth,
    loading,
  } = useDashboard()

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Security Dashboard</h1>
        <p className="text-gray-400 mt-1">Real-time network security monitoring and threat detection</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Packets Analyzed"
          value={stats ? formatNumber(stats.packets_analyzed) : '0'}
          icon={Activity}
          iconColor="text-primary-500"
          loading={loading}
        />
        <StatCard
          title="Active Flows"
          value={stats ? formatNumber(stats.active_flows) : '0'}
          icon={TrendingUp}
          iconColor="text-success"
          loading={loading}
        />
        <StatCard
          title="Alerts Today"
          value={stats ? stats.alerts_today : '0'}
          icon={AlertTriangle}
          iconColor="text-warning"
          loading={loading}
        />
        <StatCard
          title="Critical Alerts"
          value={stats ? stats.critical_alerts : '0'}
          icon={Shield}
          iconColor="text-danger"
          loading={loading}
        />
      </div>

      {/* Additional Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard
          title="High Risk Sources"
          value={stats ? stats.high_risk_sources : '0'}
          icon={Zap}
          iconColor="text-orange-500"
          loading={loading}
        />
        <StatCard
          title="Traffic Volume"
          value={stats ? formatBytes(stats.total_bytes) : '0 B'}
          icon={Activity}
          iconColor="text-blue-500"
          loading={loading}
        />
        <StatCard
          title="Events/Second"
          value={stats ? stats.events_per_second.toFixed(1) : '0'}
          icon={TrendingUp}
          iconColor="text-green-500"
          loading={loading}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrafficChart data={trafficData} loading={loading} />
        <ProtocolChart data={protocolData} loading={loading} />
      </div>

      {/* Alert Feed and Top Hosts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AlertFeed initialAlerts={recentAlerts} />
        </div>
        <div>
          <SystemHealth status={systemHealth || {}} loading={loading} />
        </div>
      </div>

      {/* Top Sources and Destinations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopHosts title="Top Source IPs" hosts={topSources} loading={loading} />
        <TopHosts title="Top Destination IPs" hosts={topDestinations} loading={loading} />
      </div>
    </div>
  )
}
