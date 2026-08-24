import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts'
import Card from '../common/Card'

interface ProtocolData {
  protocol: string
  count: number
  percentage: number
}

interface ProtocolChartProps {
  data: ProtocolData[]
  loading?: boolean
}

const COLORS = ['#00d9ff', '#00ff88', '#ffaa00', '#ff3366', '#9333ea', '#3b82f6']

export default function ProtocolChart({ data, loading = false }: ProtocolChartProps) {
  if (loading) {
    return (
      <Card title="Protocol Distribution">
        <div className="h-80 flex items-center justify-center">
          <div className="animate-pulse text-gray-500">Loading protocol data...</div>
        </div>
      </Card>
    )
  }

  if (!data || data.length === 0) {
    return (
      <Card title="Protocol Distribution">
        <div className="h-80 flex items-center justify-center text-gray-500">
          No protocol data available
        </div>
      </Card>
    )
  }

  const renderLabel = (entry: ProtocolData) => {
    return `${entry.protocol} (${entry.percentage.toFixed(1)}%)`
  }

  return (
    <Card title="Protocol Distribution">
      <ResponsiveContainer width="100%" height={320}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={renderLabel}
            outerRadius={100}
            fill="#8884d8"
            dataKey="count"
          >
            {data.map((_, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1a1f35',
              border: '1px solid #2a3150',
              borderRadius: '8px',
              color: '#fff',
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </Card>
  )
}
