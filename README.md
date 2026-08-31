# Advanced Network Intrusion Detection System (IDS)

A Python/FastAPI-based network intrusion detection and monitoring platform for learning and SOC-style security workflows.

> **Project status:** Active development. Some production-oriented features described below are implemented while others are still being hardened. This project is intended for authorized networks and lab environments.

## Key Features

- Real-time packet capture and flow tracking with Scapy
- Port-scan, brute-force, ARP-spoofing, DNS and traffic-anomaly detection
- Event correlation and incident/attack-chain analysis
- Explainable risk scoring
- MITRE ATT&CK technique mapping
- JWT authentication and role-based access control
- REST API with FastAPI
- WebSocket event streaming
- React dashboard for alerts, incidents and network activity
- SQLite support for local development; PostgreSQL for deployment

## Architecture

```text
Network Interface
       |
       v
Packet Capture -> Packet Parser -> Flow Tracker
       |
       +--> Detection Rules
       |
       v
Correlation Engine -> Risk Scoring -> Database
       |
       +--> FastAPI REST API
       +--> WebSocket Event Stream
       +--> React Dashboard
```

## Technology Stack

**Backend:** Python 3.11+, FastAPI, SQLAlchemy, Scapy, Alembic, WebSocket

**Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Recharts, Zustand, Axios

**Database:** SQLite (development) / PostgreSQL (deployment)

## Quick Start

### 1. Backend

```bash
git clone https://github.com/wwwsahilchand123-maker/Advanced-Network-IDS.git
cd Advanced-Network-IDS/backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
# source venv/bin/activate

pip install -r requirements.txt
```

Copy the example environment file to `.env` and set your own values. **Do not commit `.env`.**

```bash
uvicorn app.main:app --reload
```

API documentation:

- http://localhost:8000/api/v1/docs
- http://localhost:8000/api/v1/redoc
- http://localhost:8000/health

### 2. Frontend

```bash
cd ../frontend
npm install
npm run dev
```

The Vite development server normally runs on port 5173.

## Security Configuration

Before using the system beyond a local development environment:

- Set a strong random `SECRET_KEY` in `.env`.
- Set a unique `ADMIN_PASSWORD`.
- Set `DEBUG=False`.
- Restrict `BACKEND_CORS_ORIGINS` to trusted frontend origins.
- Use PostgreSQL for multi-user/production deployments.
- Keep API keys and credentials out of Git.
- Run packet capture only on networks you own or are explicitly authorized to monitor.

Example `.env` values:

```env
ENVIRONMENT=development
DEBUG=False
SECRET_KEY=<generate-a-long-random-secret>
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@ids.local
ADMIN_PASSWORD=<set-a-strong-password>
DATABASE_URL=sqlite:///./ids.db
```

## Detection Modules

The project includes modules for:

- Port scan detection
- Brute-force detection
- ARP spoofing detection
- DNS anomaly detection
- Traffic anomaly detection
- Suspicious traffic pattern detection
- Event correlation and incident construction

Detection thresholds should be tuned against the network being monitored. Detection results are indicators, not proof of malicious activity, and should be investigated before response actions.

## Testing

Run backend tests from the `backend` directory:

```bash
pytest
pytest --cov=app --cov-report=html
```

For manual testing and lab scenarios, see `TESTING_GUIDE.md`.

## Project Structure

```text
Advanced-Network-IDS/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── capture/
│   │   ├── correlation/
│   │   ├── core/
│   │   ├── detection/
│   │   ├── models/
│   │   ├── services/
│   │   └── main.py
│   ├── alembic/
│   └── requirements.txt
├── frontend/
├── detection_rules/
├── TESTING_GUIDE.md
├── .env.example
└── README.md
```

## Limitations

This is a portfolio/educational IDS rather than a replacement for mature commercial or open-source network security platforms. Detection quality depends on traffic visibility, thresholds, feature extraction and test coverage. Performance figures should be treated as environment-dependent unless reproduced with the included tests.

## License

MIT License. See `LICENSE`.
