import { Severity, AlertStatus } from '@/types'

interface BadgeProps {
  text: string
  variant?: 'info' | 'low' | 'medium' | 'high' | 'critical' | 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'
  className?: string
}

export default function Badge({ text, variant = 'info', className = '' }: BadgeProps) {
  const variantClasses: Record<string, string> = {
    info: 'badge-info',
    low: 'badge-low',
    medium: 'badge-medium',
    high: 'badge-high',
    critical: 'badge-critical',
    new: 'badge-new',
    acknowledged: 'badge-acknowledged',
    investigating: 'badge-investigating',
    resolved: 'badge-resolved',
    false_positive: 'badge-false-positive',
  }

  return (
    <span className={`badge ${variantClasses[variant] || variantClasses.info} ${className}`}>
      {text}
    </span>
  )
}

// Helper function to get severity badge
export function SeverityBadge({ severity }: { severity: Severity }) {
  const variantMap: Record<Severity, BadgeProps['variant']> = {
    INFO: 'info',
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical',
  }

  return <Badge text={severity} variant={variantMap[severity]} />
}

// Helper function to get status badge
export function StatusBadge({ status }: { status: AlertStatus }) {
  const displayText: Record<AlertStatus, string> = {
    new: 'New',
    acknowledged: 'Acknowledged',
    investigating: 'Investigating',
    resolved: 'Resolved',
    false_positive: 'False Positive',
  }

  return <Badge text={displayText[status]} variant={status} />
}
