import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { format } from 'date-fns'
import Card from '../common/Card'

interface TrafficDataPoint {
  timestamp: string
  packets: number
  bytes: number
}

interface TrafficChartProps {
  data: TrafficDataPoint[]
  loading?: boolean
}

export default function TrafficChart({ data, loading = false }: TrafficChartProps) {
  const formatXAxis = (timestamp: string) => {
    try {
      return format(new Date(timestamp), 'HH:mm')
    } catch {
      return timestamp
    }
  }

  const formatTooltip = (value: number, name: string) => {
    if (name === 'bytes') {
      return [formatBytes(value), 'Bytes']
    }
    return [value.toLocaleString(), 'Packets']
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  if (loading) {
    return (
      <Card title="Traffic Over Time">
        <div className="h-80 flex items-center justify-center">
          <div className="animate-pulse text-gray-500">Loading chart data...</div>
        </div>
      </Card>
    )
  }

  return (
    <Card title="Traffic Over Time">
      <ResponsiveContainer width="100%" height={320}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2a3150" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={formatXAxis}
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
          />
          <YAxis
            yAxisId="left"
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
            tickFormatter={(value) => value.toLocaleString()}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            stroke="#6b7280"
            style={{ fontSize: '12px' }}
            tickFormatter={(value) => formatBytes(value)}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1a1f35',
              border: '1px solid #2a3150',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={formatTooltip}
          />
          <Legend />
          <Line
            yAxisId="left"
            type="monotone"
            dataKey="packets"
            stroke="#00d9ff"
            strokeWidth={2}
            dot={false}
            name="Packets"
          />
          <Line
            yAxisId="right"
            type="monotone"
            dataKey="bytes"
            stroke="#00ff88"
            strokeWidth={2}
            dot={false}
            name="Bytes"
          />
        </LineChart>
      </ResponsiveContainer>
    </Card>
  )
}
