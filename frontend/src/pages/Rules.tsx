import { Shield, BookOpen, AlertTriangle, Info } from 'lucide-react'

const ruleCategories = [
  {
    name: 'Port Scan Detection',
    description: 'Detects horizontal and vertical port scanning attempts',
    severity: 'high',
    enabled: true,
    rules: 3,
  },
  {
    name: 'DDoS Detection',
    description: 'Identifies distributed denial-of-service attack patterns',
    severity: 'critical',
    enabled: true,
    rules: 5,
  },
  {
    name: 'Brute Force Detection',
    description: 'Detects repeated authentication failure patterns',
    severity: 'high',
    enabled: true,
    rules: 2,
  },
  {
    name: 'DNS Anomaly Detection',
    description: 'Identifies suspicious DNS query patterns and tunneling',
    severity: 'medium',
    enabled: true,
    rules: 4,
  },
  {
    name: 'Protocol Anomaly',
    description: 'Detects unusual protocol behavior and malformed packets',
    severity: 'medium',
    enabled: true,
    rules: 6,
  },
  {
    name: 'Data Exfiltration',
    description: 'Monitors for large outbound data transfers',
    severity: 'critical',
    enabled: true,
    rules: 3,
  },
]

const severityColors: Record<string, string> = {
  low: 'badge-low',
  medium: 'badge-medium',
  high: 'badge-high',
  critical: 'badge-critical',
}

export default function Rules() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Detection Rules</h1>
          <p className="text-gray-400 mt-1">Manage intrusion detection and alerting rules</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <BookOpen size={16} />
          <span>{ruleCategories.reduce((sum, c) => sum + c.rules, 0)} total rules</span>
        </div>
      </div>

      {/* Info Banner */}
      <div className="card card-body flex items-start gap-3 bg-primary-900/10 border-primary-800">
        <Info className="text-primary-400 mt-0.5 flex-shrink-0" size={20} />
        <div>
          <p className="text-sm text-gray-300">
            Detection rules are loaded from the <code className="text-primary-400">detection_rules/</code> directory.
            Rules are evaluated in real-time against captured network traffic to generate alerts.
          </p>
        </div>
      </div>

      {/* Rule Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {ruleCategories.map((category) => (
          <div key={category.name} className="card card-body">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-primary-900/30 rounded-lg mt-0.5">
                  <Shield className="text-primary-500" size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-gray-100">{category.name}</h3>
                  <p className="text-sm text-gray-400 mt-1">{category.description}</p>
                  <div className="flex items-center gap-3 mt-3">
                    <span className={`badge ${severityColors[category.severity]}`}>
                      {category.severity}
                    </span>
                    <span className="text-xs text-gray-500">
                      {category.rules} rules
                    </span>
                  </div>
                </div>
              </div>
              <div
                className={`w-3 h-3 rounded-full mt-1 ${
                  category.enabled ? 'bg-success' : 'bg-gray-600'
                }`}
                title={category.enabled ? 'Enabled' : 'Disabled'}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Detection Rules Directory */}
      <div className="card card-body">
        <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center gap-2">
          <AlertTriangle className="text-warning" size={20} />
          Rule Engine Info
        </h2>
        <div className="space-y-3 text-sm">
          <div className="flex justify-between py-2 border-b border-dark-50">
            <span className="text-gray-400">Rules Directory</span>
            <span className="text-gray-200 font-mono">./detection_rules</span>
          </div>
          <div className="flex justify-between py-2 border-b border-dark-50">
            <span className="text-gray-400">Baseline Calculation Interval</span>
            <span className="text-gray-200">3600 seconds</span>
          </div>
          <div className="flex justify-between py-2 border-b border-dark-50">
            <span className="text-gray-400">Correlation Time Window</span>
            <span className="text-gray-200">300 seconds</span>
          </div>
          <div className="flex justify-between py-2">
            <span className="text-gray-400">Engine Status</span>
            <span className="text-success font-medium">Active</span>
          </div>
        </div>
      </div>
    </div>
  )
}
