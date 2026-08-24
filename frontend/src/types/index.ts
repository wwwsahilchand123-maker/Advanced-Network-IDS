// Common types used across the application

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type AlertStatus = 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved'

export interface User {
  id: number
  username: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  created_at: string
  last_login?: string
}

export interface Alert {
  id: number
  alert_uuid: string
  rule_id?: string
  title: string
  description?: string
  category?: string
  severity: Severity
  confidence?: number
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol?: string
  evidence?: Record<string, any>
  mitre_attack_id?: string
  timestamp: string
  status: AlertStatus
  assigned_to?: number
  resolution_notes?: string
  resolved_at?: string
  resolved_by?: number
}

export interface Incident {
  id: number
  incident_uuid: string
  title: string
  description?: string
  severity: Severity
  risk_score: number
  status: IncidentStatus
  src_ip?: string
  dst_ips?: string[]
  attack_chain?: any
  first_seen: string
  last_seen: string
  alert_count: number
  affected_hosts: number
  mitre_techniques?: string[]
  assigned_to?: number
  created_at: string
  resolved_at?: string
}

export interface DashboardStats {
  packets_analyzed: number
  active_flows: number
  alerts_today: number
  critical_alerts: number
  high_risk_sources: number
  total_bytes: number
  events_per_second: number
}

export interface TimeSeriesData {
  timestamp: string
  value: number
  label?: string
}

export interface ProtocolDistribution {
  protocol: string
  count: number
  percentage: number
}

export interface TopHost {
  ip_address: string
  packets?: number
  bytes?: number
  flow_count?: number
  alert_count?: number
  risk_score?: number
}

export interface WebSocketMessage {
  type: 'connection_established' | 'new_alert' | 'incident_update' | 'stats_update' | 'flow_update' | 'system_message' | 'pong'
  data?: any
  message?: string
  timestamp: string
  level?: 'info' | 'warning' | 'error'
}
