import { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  icon: LucideIcon
  trend?: {
    value: number
    isPositive: boolean
  }
  iconColor?: string
  loading?: boolean
}

export default function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  iconColor = 'text-primary-500',
  loading = false,
}: StatCardProps) {
  return (
    <div className="card hover:shadow-xl transition-shadow duration-200">
      <div className="card-body">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-400">{title}</p>
            {loading ? (
              <div className="h-8 w-24 bg-dark-400 animate-pulse rounded mt-2" />
            ) : (
              <p className="text-3xl font-bold text-gray-100 mt-2">{value}</p>
            )}
            {trend && !loading && (
              <p className={`text-xs mt-2 ${trend.isPositive ? 'text-success' : 'text-danger'}`}>
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </p>
            )}
          </div>
          <div className={`p-3 rounded-lg bg-dark-400 ${iconColor}`}>
            <Icon size={24} />
          </div>
        </div>
      </div>
    </div>
  )
}
