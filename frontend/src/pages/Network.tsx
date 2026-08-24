import { useState, useEffect } from 'react'
import { Activity, Wifi, WifiOff, Radio, ArrowUpDown, Clock } from 'lucide-react'
import api from '@/lib/api'
import LoadingSpinner from '@/components/common/LoadingSpinner'

interface CaptureStatus {
  is_running: boolean
  statistics: {
    packets_captured: number
    packets_analyzed: number
    bytes_processed: number
    flows_active: number
    capture_duration: number
    interface: string
  } | null
}

interface Flow {
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  packets: number
  bytes: number
  start_time: string
}

export default function Network() {
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null)
  const [flows, setFlows] = useState<Flow[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [interfaceName, setInterfaceName] = useState('eth0')

  const fetchStatus = async () => {
    try {
      const response = await api.get('/capture/status')
      setCaptureStatus(response.data)
    } catch (error) {
      console.error('Failed to fetch capture status:', error)
    }
  }

  const fetchFlows = async () => {
    try {
      const response = await api.get('/capture/flows?limit=50')
      setFlows(response.data.flows || [])
    } catch (error) {
      console.error('Failed to fetch flows:', error)
    }
  }

  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      await Promise.all([fetchStatus(), fetchFlows()])
      setLoading(false)
    }
    loadData()

    const interval = setInterval(() => {
      fetchStatus()
      fetchFlows()
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  const handleStartCapture = async () => {
    setActionLoading(true)
    try {
      await api.post('/capture/start', { interface: interfaceName })
      await fetchStatus()
    } catch (error) {
      console.error('Failed to start capture:', error)
    }
    setActionLoading(false)
  }

  const handleStopCapture = async () => {
    setActionLoading(true)
    try {
      await api.post('/capture/stop')
      await fetchStatus()
    } catch (error) {
      console.error('Failed to stop capture:', error)
    }
    setActionLoading(false)
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  const formatDuration = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    const secs = Math.floor(seconds % 60)
    return `${hrs}h ${mins}m ${secs}s`
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  const isRunning = captureStatus?.is_running || false
  const stats = captureStatus?.statistics

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Network Capture</h1>
          <p className="text-gray-400 mt-1">Monitor and capture network traffic in real-time</p>
        </div>
        <div className="flex items-center gap-3">
          {!isRunning && (
            <input
              type="text"
              value={interfaceName}
              onChange={(e) => setInterfaceName(e.target.value)}
              placeholder="Interface (e.g., eth0)"
              className="input w-48"
            />
          )}
          <button
            onClick={isRunning ? handleStopCapture : handleStartCapture}
            disabled={actionLoading}
            className={`btn flex items-center gap-2 ${
              isRunning ? 'btn-danger' : 'btn-primary'
            }`}
          >
            {actionLoading ? (
              <LoadingSpinner size="sm" />
            ) : isRunning ? (
              <WifiOff size={18} />
            ) : (
              <Wifi size={18} />
            )}
            {isRunning ? 'Stop Capture' : 'Start Capture'}
          </button>
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card card-body">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${isRunning ? 'bg-green-900/30' : 'bg-gray-700/30'}`}>
              <Radio className={isRunning ? 'text-success' : 'text-gray-500'} size={20} />
            </div>
            <div>
              <p className="text-sm text-gray-400">Status</p>
              <p className={`text-lg font-bold ${isRunning ? 'text-success' : 'text-gray-500'}`}>
                {isRunning ? 'Capturing' : 'Stopped'}
              </p>
            </div>
          </div>
        </div>

        <div className="card card-body">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary-900/30">
              <Activity className="text-primary-500" size={20} />
            </div>
            <div>
              <p className="text-sm text-gray-400">Packets Captured</p>
              <p className="text-lg font-bold text-gray-100">
                {stats?.packets_captured?.toLocaleString() || '0'}
              </p>
            </div>
          </div>
        </div>

        <div className="card card-body">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-900/30">
              <ArrowUpDown className="text-blue-400" size={20} />
            </div>
            <div>
              <p className="text-sm text-gray-400">Data Processed</p>
              <p className="text-lg font-bold text-gray-100">
                {formatBytes(stats?.bytes_processed || 0)}
              </p>
            </div>
          </div>
        </div>

        <div className="card card-body">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-900/30">
              <Clock className="text-purple-400" size={20} />
            </div>
            <div>
              <p className="text-sm text-gray-400">Duration</p>
              <p className="text-lg font-bold text-gray-100">
                {formatDuration(stats?.capture_duration || 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Active Flows Table */}
      <div className="card">
        <div className="card-body">
          <h2 className="text-xl font-bold text-gray-100 mb-4">
            Active Flows ({flows.length})
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-400 border-b border-dark-50">
                  <th className="pb-3 pr-4">Source IP</th>
                  <th className="pb-3 pr-4">Src Port</th>
                  <th className="pb-3 pr-4">Destination IP</th>
                  <th className="pb-3 pr-4">Dst Port</th>
                  <th className="pb-3 pr-4">Protocol</th>
                  <th className="pb-3 pr-4">Packets</th>
                  <th className="pb-3">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {flows.length > 0 ? (
                  flows.map((flow, index) => (
                    <tr key={index} className="border-b border-dark-50/50 hover:bg-dark-300/50">
                      <td className="py-3 pr-4 font-mono text-gray-200">{flow.src_ip}</td>
                      <td className="py-3 pr-4 text-gray-400">{flow.src_port}</td>
                      <td className="py-3 pr-4 font-mono text-gray-200">{flow.dst_ip}</td>
                      <td className="py-3 pr-4 text-gray-400">{flow.dst_port}</td>
                      <td className="py-3 pr-4">
                        <span className="badge badge-info">{flow.protocol}</span>
                      </td>
                      <td className="py-3 pr-4 text-gray-300">{flow.packets.toLocaleString()}</td>
                      <td className="py-3 text-gray-300">{formatBytes(flow.bytes)}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-gray-500">
                      {isRunning
                        ? 'Waiting for network flows...'
                        : 'Start capture to see network flows'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
