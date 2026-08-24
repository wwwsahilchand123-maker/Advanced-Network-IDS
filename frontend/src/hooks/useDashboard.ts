import { useState, useEffect, useCallback } from 'react'
import api from '@/lib/api'
import { wsClient } from '@/lib/websocket'
import { DashboardStats, Alert, TopHost, ProtocolDistribution } from '@/types'
import { toast } from 'react-hot-toast'

interface TrafficData {
  timestamp: string
  packets: number
  bytes: number
}

export function useDashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [trafficData, setTrafficData] = useState<TrafficData[]>([])
  const [protocolData, setProtocolData] = useState<ProtocolDistribution[]>([])
  const [topSources, setTopSources] = useState<TopHost[]>([])
  const [topDestinations, setTopDestinations] = useState<TopHost[]>([])
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([])
  const [systemHealth, setSystemHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  // Fetch initial data
  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true)

      const [
        statsRes,
        trafficRes,
        protocolRes,
        sourcesRes,
        destinationsRes,
        alertsRes,
        healthRes,
      ] = await Promise.all([
        api.get('/dashboard/stats'),
        api.get('/dashboard/traffic-over-time?hours=24&interval_minutes=30'),
        api.get('/dashboard/protocol-distribution'),
        api.get('/dashboard/top-sources?limit=5'),
        api.get('/dashboard/top-destinations?limit=5'),
        api.get('/alerts/?limit=10'),
        api.get('/dashboard/system-health'),
      ])

      setStats(statsRes.data)
      setTrafficData(trafficRes.data.data)
      setProtocolData(protocolRes.data.distribution)
      setTopSources(sourcesRes.data.sources)
      setTopDestinations(destinationsRes.data.destinations)
      setRecentAlerts(alertsRes.data)
      setSystemHealth(healthRes.data)
    } catch (error) {
      console.error('Error fetching dashboard data:', error)
      toast.error('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDashboardData()

    // Refresh data every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000)

    return () => clearInterval(interval)
  }, [fetchDashboardData])

  // Listen for WebSocket updates
  useEffect(() => {
    const handleStatsUpdate = (data: any) => {
      if (data?.capture) {
        setStats((prev) => ({
          ...prev,
          packets_analyzed: data.capture.packets_analyzed || 0,
          active_flows: data.capture.active_flows || 0,
          total_bytes: data.capture.total_bytes || 0,
          events_per_second: data.capture.packets_per_second || 0,
          alerts_today: prev?.alerts_today || 0,
          critical_alerts: prev?.critical_alerts || 0,
          high_risk_sources: prev?.high_risk_sources || 0,
        }))
      }
    }

    const handleNewAlert = (alert: Alert) => {
      setRecentAlerts((prev) => [alert, ...prev.slice(0, 9)])
      
      // Update alert counts
      setStats((prev) => {
        if (!prev) return null
        return {
          ...prev,
          alerts_today: prev.alerts_today + 1,
          critical_alerts: alert.severity === 'CRITICAL' 
            ? prev.critical_alerts + 1 
            : prev.critical_alerts,
        }
      })
    }

    wsClient.on('stats_update', handleStatsUpdate)
    wsClient.on('new_alert', handleNewAlert)

    return () => {
      wsClient.off('stats_update', handleStatsUpdate)
      wsClient.off('new_alert', handleNewAlert)
    }
  }, [])

  return {
    stats,
    trafficData,
    protocolData,
    topSources,
    topDestinations,
    recentAlerts,
    systemHealth,
    loading,
    refresh: fetchDashboardData,
  }
}
