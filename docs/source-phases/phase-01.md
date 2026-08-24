1. claude-sonnet-4-5-20250929

# Advanced Network Intrusion Detection System (IDS)

## Architecture & Implementation Roadmap

I'll build this production-grade IDS system phase by phase. Let me start with the complete architecture and design decisions.

---

## 🏗️ SYSTEM ARCHITECTURE

```
text
```

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Interface Layer                      │
│                  (eth0, wlan0, lo, pcap files)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                   Packet Capture Engine                          │
│         (Scapy async capture + PCAP parser)                     │
│  • Interface selection    • Packet filtering                    │
│  • Real-time capture     • PCAP upload                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                    Packet Parser Layer                           │
│         • Protocol extraction  • Header parsing                  │
│         • TCP/UDP/ICMP/DNS    • Flow identification             │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                  Flow Aggregation Engine                         │
│    • 5-tuple tracking    • Statistics aggregation               │
│    • Connection state    • Time-window analysis                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
┌───────────────────▼──┐   ┌──────────▼──────────────────────────┐
│  Baseline Builder    │   │    Detection Engine                 │
│  • Traffic profile   │   │  • Rule-based detection             │
│  • Normal behavior   │   │  • Threshold evaluation             │
│  • Statistical model │   │  • Pattern matching                 │
└───────────────────┬──┘   └──────────┬──────────────────────────┘
                    │                 │
                    └────────┬────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│              Event Correlation Engine                            │
│  • Multi-event analysis    • Attack chain detection             │
│  • Temporal correlation    • Source/target grouping             │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                 Risk Scoring Engine                              │
│  • Severity calculation    • Confidence scoring                 │
│  • MITRE ATT&CK mapping   • Evidence aggregation                │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│               Alert & Incident Manager                           │
│  • Alert lifecycle        • Incident creation                   │
│  • Deduplication         • Status management                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│              PostgreSQL Database + Redis Cache                   │
│  • Events  • Alerts  • Incidents  • Flows  • Baseline           │
│  • Users   • Audit   • Rules      • Reports                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
┌───────────────────▼──┐   ┌──────────▼──────────────────────────┐
│   REST API (FastAPI) │   │   WebSocket Server                  │
│   • CRUD operations  │   │   • Live event stream               │
│   • Authentication   │   │   • Real-time alerts                │
│   • Report generation│   │   • Dashboard updates               │
└───────────────────┬──┘   └──────────┬──────────────────────────┘
                    │                 │
                    └────────┬────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│           React + TypeScript Frontend                            │
│  • SOC Dashboard          • Investigation UI                    │
│  • Alert Management       • PCAP Analysis                       │
│  • Network Visualization  • Reporting                           │
│  • Rule Management        • User Management                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 DATABASE SCHEMA DESIGN

```
SQL
```

```
-- Users and Authentication
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL, -- admin, analyst, viewer
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Network Flows (5-tuple aggregation)
CREATE TABLE flows (
    id BIGSERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10) NOT NULL,
    src_mac VARCHAR(17),
    dst_mac VARCHAR(17),
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    packet_count INTEGER DEFAULT 0,
    byte_count BIGINT DEFAULT 0,
    tcp_flags JSONB, -- {SYN: 5, ACK: 10, FIN: 2}
    duration_ms INTEGER,
    interface VARCHAR(50),
    state VARCHAR(20), -- NEW, ESTABLISHED, CLOSED
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_first_seen (first_seen),
    INDEX idx_protocol (protocol)
);

-- Detection Rules
CREATE TABLE detection_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100), -- port_scan, brute_force, anomaly, etc.
    severity VARCHAR(20), -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    enabled BOOLEAN DEFAULT TRUE,
    threshold_config JSONB, -- {connections: 50, time_window: 10}
    cooldown_seconds INTEGER DEFAULT 300,
    mitre_attack_id VARCHAR(50),
    mitre_technique VARCHAR(255),
    detection_logic TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rule_id (rule_id),
    INDEX idx_enabled (enabled),
    INDEX idx_category (category)
);

-- Alerts
CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_uuid UUID UNIQUE NOT NULL,
    rule_id VARCHAR(50) REFERENCES detection_rules(rule_id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    severity VARCHAR(20),
    confidence INTEGER, -- 0-100
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    evidence JSONB, -- Detailed evidence data
    mitre_attack_id VARCHAR(50),
    timestamp TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'new', -- new, acknowledged, investigating, resolved, false_positive
    assigned_to INTEGER REFERENCES users(id),
    resolution_notes TEXT,
    resolved_at TIMESTAMP,
    resolved_by INTEGER REFERENCES users(id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_src_ip (src_ip),
    INDEX idx_category (category)
);

-- Incidents (Correlated alerts)
CREATE TABLE incidents (
    id SERIAL PRIMARY KEY,
    incident_uuid UUID UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    risk_score INTEGER, -- 0-100
    status VARCHAR(50) DEFAULT 'open', -- open, investigating, contained, resolved
    src_ip INET,
    dst_ips JSONB, -- Array of target IPs
    attack_chain JSONB, -- Timeline of correlated events
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    alert_count INTEGER DEFAULT 0,
    affected_hosts INTEGER DEFAULT 0,
    mitre_techniques JSONB, -- Array of technique IDs
    assigned_to INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    INDEX idx_incident_uuid (incident_uuid),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_first_seen (first_seen)
);

-- Incident-Alert relationship
CREATE TABLE incident_alerts (
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id BIGINT REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

-- Traffic Baseline (for anomaly detection)
CREATE TABLE traffic_baseline (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    baseline_value JSONB, -- {mean: 100, stddev: 15, min: 50, max: 200}
    time_period VARCHAR(50), -- hourly, daily, weekly
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sample_count INTEGER,
    INDEX idx_metric_name (metric_name)
);

-- ARP Cache (for ARP spoofing detection)
CREATE TABLE arp_cache (
    id SERIAL PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    change_count INTEGER DEFAULT 0,
    previous_macs JSONB, -- Historical MAC addresses
    INDEX idx_ip_address (ip_address)
);

-- DNS Query Log (for DNS anomaly detection)
CREATE TABLE dns_queries (
    id BIGSERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    query_type VARCHAR(10),
    response_ips JSONB,
    timestamp TIMESTAMP NOT NULL,
    query_entropy FLOAT, -- Shannon entropy for DGA detection
    INDEX idx_src_ip (src_ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_query_name (query_name)
);

-- PCAP Analysis Sessions
CREATE TABLE pcap_sessions (
    id SERIAL PRIMARY KEY,
    session_uuid UUID UNIQUE NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT,
    uploaded_by INTEGER REFERENCES users(id),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50), -- processing, completed, failed
    packet_count INTEGER,
    flow_count INTEGER,
    alert_count INTEGER,
    analysis_report JSONB,
    processed_at TIMESTAMP,
    INDEX idx_session_uuid (session_uuid),
    INDEX idx_uploaded_by (uploaded_by)
);

-- Audit Log
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    username VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    INDEX idx_user_id (user_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action)
);

-- System Configuration
CREATE TABLE system_config (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id)
);

-- Network Hosts (discovered hosts)
CREATE TABLE network_hosts (
    id SERIAL PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    packet_count INTEGER DEFAULT 0,
    connection_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    tags JSONB, -- [internal, server, workstation]
    INDEX idx_ip_address (ip_address),
    INDEX idx_last_seen (last_seen)
);

-- Threat Intelligence Cache (optional)
CREATE TABLE threat_intel (
    id SERIAL PRIMARY KEY,
    indicator VARCHAR(255) UNIQUE NOT NULL, -- IP, domain, hash
    indicator_type VARCHAR(50), -- ip, domain, hash
    threat_level VARCHAR(20),
    categories JSONB,
    source VARCHAR(100),
    confidence INTEGER,
    first_seen TIMESTAMP,
    last_checked TIMESTAMP,
    metadata JSONB,
    INDEX idx_indicator (indicator),
    INDEX idx_indicator_type (indicator_type)
);
```

---

## 🎯 DETECTION RULES SPECIFICATION

### Rule Configuration Schema

```
YAML
```

```
rule_id: "SCAN_001"
name: "TCP SYN Port Scan Detection"
description: "Detects potential port scanning activity based on SYN packet patterns"
category: "reconnaissance"
severity: "HIGH"
enabled: true
mitre_attack:
  tactic: "Discovery"
  technique: "T1046"
  technique_name: "Network Service Scanning"

detection_logic:
  type: "threshold"
  conditions:
    - metric: "unique_dst_ports_per_src"
      threshold: 25
      time_window: 10  # seconds
    - metric: "syn_to_ack_ratio"
      threshold: 0.8
    - metric: "failed_connection_ratio"
      threshold: 0.7

evidence_collection:
  - src_ip
  - dst_ip
  - contacted_ports
  - packet_timestamps
  - tcp_flags

confidence_calculation:
  base: 70
  modifiers:
    - condition: "ports_contacted > 50"
      adjustment: +15
    - condition: "sequential_ports"
      adjustment: +10
    - condition: "syn_only_packets > 90%"
      adjustment: +5

response:
  alert: true
  block: false  # This is IDS, not IPS
  correlate: true
  cooldown: 300  # seconds
```

### Core Detection Rules

1. **Port Scan Detection**
   - Vertical scan (many ports, one target)
   - Horizontal scan (one port, many targets)
   - SYN scan patterns
   - NULL/FIN/XMAS scan patterns
2. **Brute Force Detection**
   - SSH (port 22)
   - FTP (port 21)
   - HTTP Auth (ports 80, 443)
   - RDP (port 3389)
   - Multiple failed connections
3. **Network Anomalies**
   - Traffic volume spikes
   - Unusual protocol distribution
   - Connection burst patterns
   - Abnormal packet sizes
   - Protocol violations
4. **ARP Anomalies**
   - IP/MAC inconsistencies
   - ARP spoofing patterns
   - Duplicate IP assignments
   - Gateway impersonation
5. **DNS Anomalies**
   - Excessive query rates
   - High-entropy domains (DGA detection)
   - DNS tunneling indicators
   - Unusual query types
   - Suspicious TLDs
6. **Suspicious Connections**
   - Unexpected outbound connections
   - Rare destination IPs
   - Uncommon service ports
   - ICMP tunneling patterns

---

## 🔧 TECHNOLOGY STACK FINALIZED

### Backend

```
Python
```

```
fastapi==0.104.1
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
alembic==1.12.1
psycopg2-binary==2.9.9
pydantic==2.5.0
pydantic-settings==2.1.0
scapy==2.5.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
aiofiles==23.2.1
redis==5.0.1
celery==5.3.4
websockets==12.0
python-dotenv==1.0.0
pyshark==0.6  # Optional PCAP parsing
reportlab==4.0.7  # PDF generation
pandas==2.1.3  # Data analysis
numpy==1.26.2
scipy==1.11.4  # Statistical analysis
pytest==7.4.3
pytest-asyncio==0.21.1
httpx==0.25.2
```

### Frontend

```
JSON
```

```
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "typescript": "^5.3.0",
    "axios": "^1.6.0",
    "react-router-dom": "^6.20.0",
    "recharts": "^2.10.0",
    "tailwindcss": "^3.3.0",
    "lucide-react": "^0.294.0",
    "date-fns": "^2.30.0",
    "react-query": "^3.39.3",
    "zustand": "^4.4.7",
    "socket.io-client": "^4.7.0",
    "react-hot-toast": "^2.4.1",
    "react-table": "^7.8.0"
  }
}
```

### Database

- **Primary**: PostgreSQL 15+
- **Cache**: Redis 7+
- **Development Fallback**: SQLite

---

## 📁 PROJECT STRUCTURE

```
text
```

```
advanced-ids/
│
├── backend/
│   ├── alembic/                    # Database migrations
│   │   ├── versions/
│   │   └── env.py
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI application entry
│   │   │
│   │   ├── api/                    # API endpoints
│   │   │   ├── __init__.py
│   │   │   ├── deps.py            # Dependencies
│   │   │   ├── auth.py            # Authentication endpoints
│   │   │   ├── dashboard.py       # Dashboard statistics
│   │   │   ├── alerts.py          # Alert management
│   │   │   ├── incidents.py       # Incident management
│   │   │   ├── flows.py           # Network flows
│   │   │   ├── rules.py           # Detection rules
│   │   │   ├── pcap.py            # PCAP analysis
│   │   │   ├── reports.py         # Report generation
│   │   │   ├── users.py           # User management
│   │   │   ├── audit.py           # Audit logs
│   │   │   └── websocket.py       # WebSocket endpoints
│   │   │
│   │   ├── core/                   # Core configuration
│   │   │   ├── __init__.py
│   │   │   ├── config.py          # Settings
│   │   │   ├── security.py        # Auth/crypto
│   │   │   └── logging.py         # Logging setup
│   │   │
│   │   ├── models/                 # SQLAlchemy models
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── flow.py
│   │   │   ├── alert.py
│   │   │   ├── incident.py
│   │   │   ├── rule.py
│   │   │   ├── baseline.py
│   │   │   ├── arp_cache.py
│   │   │   ├── dns_query.py
│   │   │   ├── pcap_session.py
│   │   │   ├── audit_log.py
│   │   │   └── network_host.py
│   │   │
│   │   ├── schemas/                # Pydantic schemas
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── alert.py
│   │   │   ├── incident.py
│   │   │   ├── flow.py
│   │   │   ├── rule.py
│   │   │   ├── dashboard.py
│   │   │   └── report.py
│   │   │
│   │   ├── capture/                # Packet capture engine
│   │   │   ├── __init__.py
│   │   │   ├── engine.py          # Main capture logic
│   │   │   ├── parser.py          # Packet parsing
│   │   │   ├── flow_tracker.py    # Flow aggregation
│   │   │   └── pcap_analyzer.py   # PCAP file analysis
│   │   │
│   │   ├── detection/              # Detection engine
│   │   │   ├── __init__.py
│   │   │   ├── engine.py          # Main detection engine
│   │   │   ├── rule_manager.py    # Rule loading/management
│   │   │   ├── detectors/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── port_scan.py
│   │   │   │   ├── brute_force.py
│   │   │   │   ├── anomaly.py
│   │   │   │   ├── arp_spoofing.py
│   │   │   │   ├── dns_anomaly.py
│   │   │   │   └── suspicious_traffic.py
│   │   │   └── baseline.py        # Baseline calculation
│   │   │
│   │   ├── correlation/            # Event correlation
│   │   │   ├── __init__.py
│   │   │   ├── engine.py          # Correlation logic
│   │   │   ├── incident_builder.py
│   │   │   └── attack_chains.py   # Attack pattern detection
│   │   │
│   │   ├── scoring/                # Risk scoring
│   │   │   ├── __init__.py
│   │   │   ├── risk_calculator.py
│   │   │   ├── severity_mapper.py
│   │   │   └── mitre_mapper.py    # MITRE ATT&CK mapping
│   │   │
│   │   ├── services/               # Business logic
│   │   │   ├── __init__.py
│   │   │   ├── alert_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── flow_service.py
│   │   │   ├── user_service.py
│   │   │   ├── rule_service.py
│   │   │   ├── dashboard_service.py
│   │   │   ├── pcap_service.py
│   │   │   └── audit_service.py
│   │   │
│   │   ├── reporting/              # Report generation
│   │   │   ├── __init__.py
│   │   │   ├── pdf_generator.py
│   │   │   ├── csv_exporter.py
│   │   │   └── templates/
│   │   │
│   │   ├── threat_intel/           # Threat intelligence (optional)
│   │   │   ├── __init__.py
│   │   │   ├── provider.py
│   │   │   └── enrichment.py
│   │   │
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── network.py         # Network utilities
│   │       ├── entropy.py         # Entropy calculation
│   │       └── validators.py
│   │
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_api/
│   │   ├── test_detection/
│   │   ├── test_correlation/
│   │   ├── test_capture/
│   │   └── fixtures/
│   │       └── sample.pcap
│   │
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── pytest.ini
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   ├── Header.tsx
│   │   │   │   └── Layout.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── StatCard.tsx
│   │   │   │   ├── TrafficChart.tsx
│   │   │   │   ├── AlertFeed.tsx
│   │   │   │   ├── ProtocolDistribution.tsx
│   │   │   │   └── NetworkMap.tsx
│   │   │   ├── alerts/
│   │   │   │   ├── AlertTable.tsx
│   │   │   │   ├── AlertDetail.tsx
│   │   │   │   └── AlertFilter.tsx
│   │   │   ├── incidents/
│   │   │   │   ├── IncidentTable.tsx
│   │   │   │   ├── IncidentDetail.tsx
│   │   │   │   ├── Timeline.tsx
│   │   │   │   └── Evidence.tsx
│   │   │   ├── rules/
│   │   │   ├── pcap/
│   │   │   └── common/
│   │   │       ├── Badge.tsx
│   │   │       ├── Table.tsx
│   │   │       ├── Modal.tsx
│   │   │       └── Chart.tsx
│   │   │
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Alerts.tsx
│   │   │   ├── Incidents.tsx
│   │   │   ├── Investigation.tsx
│   │   │   ├── Rules.tsx
│   │   │   ├── PcapAnalysis.tsx
│   │   │   ├── Reports.tsx
│   │   │   ├── Network.tsx
│   │   │   ├── Settings.tsx
│   │   │   └── Login.tsx
│   │   │
│   │   ├── services/
│   │   │   ├── api.ts
│   │   │   ├── websocket.ts
│   │   │   └── auth.ts
│   │   │
│   │   ├── hooks/
│   │   │   ├── useAuth.ts
│   │   │   ├── useWebSocket.ts
│   │   │   ├── useAlerts.ts
│   │   │   └── useDashboard.ts
│   │   │
│   │   ├── types/
│   │   │   ├── alert.ts
│   │   │   ├── incident.ts
│   │   │   ├── flow.ts
│   │   │   └── user.ts
│   │   │
│   │   ├── store/
│   │   │   └── authStore.ts
│   │   │
│   │   ├── utils/
│   │   │   ├── formatters.ts
│   │   │   └── validators.ts
│   │   │
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   │
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── detection_rules/                # Detection rule definitions
│   ├── port_scan.yaml
│   ├── brute_force.yaml
│   ├── arp_spoofing.yaml
│   ├── dns_anomaly.yaml
│   └── traffic_anomaly.yaml
│
├── scripts/
│   ├── init_db.py                 # Database initialization
│   ├── create_admin.py            # Create admin user
│   ├── demo_mode.py               # Generate demo data
│   ├── import_rules.py            # Import detection rules
│   └── cleanup.py                 # Data retention cleanup
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── DETECTION_RULES.md
│   ├── DEPLOYMENT.md
│   └── SCREENSHOTS.md
│
├── pcaps/                          # Sample PCAP files
│   └── README.md
│
├── reports/                        # Generated reports
│   └── .gitkeep
│
├── docker/
│   ├── backend.Dockerfile
│   ├── frontend.Dockerfile
│   └── nginx.conf
│
├── .env.example
├── .gitignore
├── docker-compose.yml
├── docker-compose.dev.yml
├── README.md
├── LICENSE
└── Makefile
```

---

## 🚀 IMPLEMENTATION PHASES

### Phase 1: Foundation ✅ (Current)

-  Architecture design
-  Database schema
-  Technology stack selection
-  Project structure
-  Detection rule specification

### Phase 2: Backend Core (Next)

-  FastAPI application setup
-  Database models (SQLAlchemy)
-  Pydantic schemas
-  Database migrations (Alembic)
-  Configuration management
-  Logging setup

### Phase 3: Authentication & Security

-  User model and authentication
-  JWT token handling
-  Password hashing
-  RBAC implementation
-  Audit logging
-  API security middleware

### Phase 4: Packet Capture Engine

-  Scapy capture implementation
-  Packet parser
-  Flow tracking
-  PCAP file analyzer
-  Capture management API

### Phase 5: Detection Engine

-  Rule manager
-  Port scan detector
-  Brute force detector
-  ARP spoofing detector
-  DNS anomaly detector
-  Traffic anomaly detector
-  Baseline builder

### Phase 6: Correlation & Scoring

-  Event correlation engine
-  Incident builder
-  Risk scoring calculator
-  MITRE ATT&CK mapper
-  Attack chain detection

### Phase 7: Alert & Incident Management

-  Alert service
-  Incident service
-  Alert lifecycle management
-  Deduplication
-  Status management

### Phase 8: REST API

-  Dashboard endpoints
-  Alert endpoints
-  Incident endpoints
-  Flow endpoints
-  Rule endpoints
-  PCAP endpoints
-  Report endpoints
-  User management endpoints

### Phase 9: WebSocket Real-time

-  WebSocket server
-  Live event streaming
-  Real-time alert broadcasting
-  Dashboard updates

### Phase 10: Frontend Dashboard

-  React setup
-  Authentication UI
-  Dashboard page
-  Live statistics
-  Traffic visualizations
-  Alert feed

### Phase 11: Frontend - Alerts & Incidents

-  Alert table and filtering
-  Alert detail view
-  Incident investigation UI
-  Timeline visualization
-  Evidence display

### Phase 12: Frontend - Analysis & Reports

-  PCAP upload and analysis
-  Network visualization
-  Rule management UI
-  Report generation UI
-  Settings page

### Phase 13: Reporting

-  PDF report generator
-  CSV export
-  Incident reports
-  Executive summary

### Phase 14: Demo Mode

-  Synthetic event generator
-  Simulated alerts
-  Demo data population

### Phase 15: Testing

-  Unit tests
-  Integration tests
-  API tests
-  Detection engine tests
-  Test fixtures

### Phase 16: Deployment

-  Docker images
-  Docker Compose
-  Environment configuration
-  Deployment documentation
-  Performance optimization

### Phase 17: Documentation

-  Comprehensive README
-  API documentation
-  Architecture documentation
-  User guide
-  Screenshots

---

## 🎨 UI/UX DESIGN PRINCIPLES

### Color Scheme (Cybersecurity Theme)

```
CSS
```

```
/* Dark theme */
--background: #0a0e1a
--surface: #1a1f35
--surface-hover: #252b45
--primary: #00d9ff
--primary-dark: #0099cc
--success: #00ff88
--warning: #ffaa00
--danger: #ff3366
--critical: #ff0044
--text-primary: #ffffff
--text-secondary: #b4b9d0
--border: #2a3150
```

### Dashboard Layout

```
text
```

```
┌─────────────────────────────────────────────────────────┐
│  [Logo] Advanced IDS          [User] [Settings] [Logout]│
├──────┬──────────────────────────────────────────────────┤
│      │  📊 Dashboard Statistics                         │
│ Nav  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐               │
│      │  │Pkts │ │Flows│ │Alerts│ │Crit │               │
│ 🏠   │  │ 1.2M│ │ 45K │ │  127│ │  12 │               │
│ 🚨   │  └─────┘ └─────┘ └─────┘ └─────┘               │
│ 📁   │                                                   │
│ 🔍   │  📈 Traffic Over Time                           │
│ ⚙️   │  [────────────Chart────────────]                │
│ 👥   │                                                   │
│ 📊   │  Live Alert Feed        Protocol Distribution   │
│      │  ┌──────────────┐      ┌──────────────┐        │
│      │  │[HIGH] Port   │      │  TCP: 65%    │        │
│      │  │[CRIT] Brute  │      │  UDP: 25%    │        │
│      │  │[MED] DNS     │      │  ICMP: 8%    │        │
│      │  └──────────────┘      └──────────────┘        │
└──────┴──────────────────────────────────────────────────┘
```

---

## 🔐 SECURITY CONSIDERATIONS

1. **Authentication**
   - Bcrypt password hashing (cost factor: 12)
   - JWT with short expiration (15 min access, 7 day refresh)
   - Secure session management
   - Rate limiting on auth endpoints
2. **Input Validation**
   - Pydantic schema validation
   - SQL injection prevention (SQLAlchemy ORM)
   - XSS prevention
   - File upload validation
3. **Network Capture**
   - Requires root/CAP\_NET\_RAW
   - No payload storage by default
   - Metadata-only retention
   - Configurable capture filters
4. **Data Protection**
   - No plaintext passwords
   - Secrets in environment variables
   - Database encryption at rest (PostgreSQL config)
   - HTTPS in production
5. **RBAC**
   - Admin: Full access
   - Analyst: Read/write alerts, incidents
   - Viewer: Read-only access

---

## 📋 DEPLOYMENT COMMANDS (Preview)

```
Bash
```

```
# Development
make install          # Install dependencies
make migrate          # Run database migrations
make admin            # Create admin user
make dev              # Run development server
make demo             # Start demo mode

# Docker
make docker-build     # Build Docker images
make docker-up        # Start containers
make docker-logs      # View logs

# Testing
make test             # Run all tests
make test-coverage    # Run with coverage

# Production
make prod             # Production deployment
```

---

## ✅ PHASE 1 COMPLETE

**Status**: Architecture, database schema, detection rules, and project structure designed.

**Next Phase**: Begin implementation with Phase 2 (Backend Core).

Would you like me to proceed with **Phase 2: Backend Core Implementation**? This will include:

1. FastAPI application setup
2. SQLAlchemy models
3. Pydantic schemas
4. Database configuration
5. Alembic migrations
6. Core utilities

Respond with "**START PHASE 2**" to continue, or ask questions about the architecture.