# Advanced IDS - Complete Testing Guide

## Prerequisites

- Python 3.11+
- PostgreSQL 15+ (or SQLite for testing)
- Node.js 18+
- Root/admin privileges (for packet capture)

---

## Backend Setup & Testing

### 1. Initial Setup

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Edit .env and configure:
# - DATABASE_URL (PostgreSQL or SQLite)
# - SECRET_KEY (generate with: python -c "import secrets; print(secrets.token_urlsafe(32))")
# - ADMIN credentials

### 2. Database Initialization

```
Bash
```

```
# Initialize database tables
python scripts/init_db.py

# Run migrations (if using Alembic)
alembic upgrade head

# Create admin user
python scripts/create_admin.py

# Verify admin created
# Check logs for: "Admin user created successfully!"
```

### 3. Start Backend Server

```
Bash
```

```
# Development mode (with auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or using Makefile
make dev

# Verify server started:
# Open: http://localhost:8000
# Should see: {"name":"Advanced IDS","version":"1.0.0","status":"running"}

# Check API docs:
# Open: http://localhost:8000/api/v1/docs
```

### 4. Test Authentication API

```
Bash
```

```
# Test login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=ChangeThisPassword123!"

# Expected response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#   "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#   "token_type": "bearer"
# }

# Save token for subsequent requests
export TOKEN="your_access_token_here"

# Test authenticated endpoint
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Test Packet Capture (Requires Root)

```
Bash
```

```
# Option 1: Run as root
sudo uvicorn app.main:app --host 0.0.0.0 --port 8000

# Option 2: Grant capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)

# Start capture on loopback (safe for testing)
curl -X POST http://localhost:8000/api/v1/capture/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface": "lo"}'

# Check capture status
curl http://localhost:8000/api/v1/capture/status \
  -H "Authorization: Bearer $TOKEN"

# Generate test traffic
ping -c 10 localhost

# Check statistics
curl http://localhost:8000/api/v1/capture/status \
  -H "Authorization: Bearer $TOKEN"

# Stop capture
curl -X POST http://localhost:8000/api/v1/capture/stop \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Test Detection Engine

```
Bash
```

```
# Start capture
curl -X POST http://localhost:8000/api/v1/capture/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface": "lo"}'

# Simulate port scan (authorized lab environment ONLY!)
# WARNING: Only run on YOUR OWN systems
nmap -sS localhost -p 1-100  # Will trigger port scan detection

# Check alerts
curl http://localhost:8000/api/v1/alerts/ \
  -H "Authorization: Bearer $TOKEN"

# Get alert statistics
curl http://localhost:8000/api/v1/alerts/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Test WebSocket Real-Time Updates

```
Bash
```

```
# In another terminal, run WebSocket client
python websocket_client_example.py

# You should see:
# - Connection established
# - Periodic stats updates
# - Live alerts when generated
# - Flow updates

# Generate traffic to see live updates
ping -c 100 localhost
```

### 8. Test Dashboard API

```
Bash
```

```
# Get dashboard statistics
curl http://localhost:8000/api/v1/dashboard/stats \
  -H "Authorization: Bearer $TOKEN"

# Get traffic over time
curl "http://localhost:8000/api/v1/dashboard/traffic-over-time?hours=24" \
  -H "Authorization: Bearer $TOKEN"

# Get protocol distribution
curl http://localhost:8000/api/v1/dashboard/protocol-distribution \
  -H "Authorization: Bearer $TOKEN"

# Get top sources
curl http://localhost:8000/api/v1/dashboard/top-sources \
  -H "Authorization: Bearer $TOKEN"
```

### 9. Run Unit Tests

```
Bash
```

```
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test module
pytest tests/test_detection/

# View coverage report
open htmlcov/index.html
```

---

## Frontend Setup & Testing

### 1. Initial Setup

```
Bash
```

```
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Verify .env contains:
# VITE_API_URL=http://localhost:8000
# VITE_WS_URL=ws://localhost:8000
```

### 2. Start Frontend

```
Bash
```

```
# Development mode
npm run dev

# Frontend starts on: http://localhost:3000

# Build for production
npm run build

# Preview production build
npm run preview
```

### 3. Test Login Flow

```
text
```

```
1. Open: http://localhost:3000
2. Should redirect to /login
3. Enter credentials:
   - Username: admin
   - Password: ChangeThisPassword123!
4. Click "Sign In"
5. Should redirect to Dashboard
6. Verify header shows: "Welcome back, admin"
```

### 4. Test Dashboard

```
text
```

```
✓ Check stat cards update
✓ Verify traffic chart displays
✓ Check protocol distribution chart
✓ Verify live alert feed
✓ Check system health indicators
✓ Verify top sources/destinations display

Real-time updates (with backend running):
✓ Stats update every 5 seconds
✓ New alerts appear in feed
✓ Charts update periodically
```

### 5. Test Alerts Page

```
text
```

```
1. Navigate to: http://localhost:3000/alerts
2. Verify alerts table displays
3. Test filters:
   - Click "Filters" button
   - Select severity: "HIGH"
   - Verify filtered results
4. Test search:
   - Enter IP address
   - Verify search works
5. Test pagination
6. Click an alert row
7. Verify modal opens
8. Test actions:
   - Acknowledge
   - Mark as False Positive
   - Change status
```

### 6. Test Incidents Page

```
text
```

```
1. Navigate to: http://localhost:3000/incidents
2. Verify incident cards display
3. Check risk scores
4. Test filtering
5. Click an incident
6. Verify investigation modal opens
7. Check timeline display
8. Verify related alerts
9. Test escalate/resolve actions
```

### 7. Test WebSocket Integration

```
text
```

```
With backend running and capture active:

1. Open browser console (F12)
2. Navigate to Dashboard
3. Start packet capture (via API or generate traffic)
4. Watch console for WebSocket messages
5. Verify:
   - Stats update in real-time
   - New alerts appear immediately
   - No connection errors
   
Expected console output:
> WebSocket connected
> stats_update received
> new_alert received
```

---

## Integration Testing

### Full System Test

```
Bash
```

```
# Terminal 1: Backend
cd backend
source venv/bin/activate
make dev

# Terminal 2: WebSocket Monitor
cd backend
python websocket_client_example.py

# Terminal 3: Frontend
cd frontend
npm run dev

# Terminal 4: Traffic Generator
ping -c 1000 localhost &
# Or simulate port scan (authorized only!)
```

### Test Scenario 1: Normal Traffic

```
Bash
```

```
1. Start all services
2. Open dashboard: http://localhost:3000
3. Start capture on 'lo' interface
4. Generate normal traffic: ping localhost
5. Verify:
   ✓ Packets counted
   ✓ Flows created
   ✓ No alerts generated
   ✓ Stats update in real-time
```

### Test Scenario 2: Port Scan Detection

```
Bash
```

```
# ⚠️ AUTHORIZED LAB ONLY ⚠️
1. Start capture
2. Run: nmap -sS localhost -p 1-50
3. Verify:
   ✓ Alert generated: "Port Scan Detected"
   ✓ Alert appears in dashboard feed
   ✓ Alert visible in Alerts page
   ✓ WebSocket broadcasts alert
   ✓ Evidence contains port list
```

### Test Scenario 3: Incident Creation

```
Bash
```

```
1. Generate multiple related alerts:
   - Port scan
   - Multiple connection attempts
2. Verify:
   ✓ Alerts correlate into incident
   ✓ Incident created
   ✓ Risk score calculated
   ✓ Timeline generated
   ✓ Incident visible in Incidents page
```

---

## Performance Testing

### Load Test Dashboard

```
Bash
```

```
# Keep dashboard open
# Monitor browser performance
# Generate heavy traffic
ping -c 10000 localhost &

✓ Dashboard remains responsive
✓ No memory leaks
✓ Charts update smoothly
✓ WebSocket stays connected
```

### Database Performance

```
Bash
```

```
# Generate 1000+ alerts
# Check query performance
curl http://localhost:8000/api/v1/alerts/?limit=100 \
  -H "Authorization: Bearer $TOKEN" \
  -w "\nTime: %{time_total}s\n"

# Should complete in < 2 seconds
```

---

## Troubleshooting

### Backend Issues

**Problem: "Permission denied" on packet capture**

```
Bash
```

```
Solution:
sudo uvicorn app.main:app --host 0.0.0.0 --port 8000
# Or:
sudo setcap cap_net_raw=eip $(which python)
```

**Problem: Database connection error**

```
Bash
```

```
Solution:
# Check DATABASE_URL in .env
# For SQLite: sqlite:///./ids.db
# For PostgreSQL: postgresql://user:pass@localhost/dbname

# Test connection:
python -c "from app.db.session import engine; engine.connect()"
```

**Problem: WebSocket not connecting**

```
Bash
```

```
Solution:
# Check CORS settings in backend/app/main.py
# Ensure frontend URL in BACKEND_CORS_ORIGINS
# Default: ["http://localhost:3000", "http://localhost:5173"]
```

### Frontend Issues

**Problem: API calls fail with CORS error**

```
Bash
```

```
Solution:
# Check .env: VITE_API_URL=http://localhost:8000
# Restart frontend: npm run dev
# Check backend CORS middleware
```

**Problem: WebSocket disconnects**

```
Bash
```

```
Solution:
# Check browser console for errors
# Verify WebSocket URL in .env
# Check token validity
# Backend logs for WebSocket errors
```

**Problem: Login fails**

```
Bash
```

```
Solution:
# Verify admin user exists:
cd backend
python scripts/create_admin.py

# Check credentials in Login.tsx default display
# Clear localStorage: localStorage.clear()
```

---

## Security Testing

### Test Authentication

```
Bash
```

```
# Test without token (should fail)
curl http://localhost:8000/api/v1/alerts/

# Test with invalid token (should fail)
curl http://localhost:8000/api/v1/alerts/ \
  -H "Authorization: Bearer invalid_token"

# Test with expired token (should refresh)
# Wait for token expiration (15 min)
```

### Test RBAC

```
Bash
```

```
# Create viewer user (admin only)
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "viewer",
    "email": "viewer@test.com",
    "password": "Test123!@#",
    "role": "viewer"
  }'

# Login as viewer
# Try to start capture (should fail - requires analyst)
```

---

## Demo Mode (No Root Required)

For testing without packet capture:

```
Bash
```

```
# Backend: Start in demo mode
# Edit .env: DEMO_MODE=True
python scripts/demo_mode.py &

# This generates synthetic:
# - Alerts
# - Incidents
# - Statistics

# Frontend works normally
# All features testable without real traffic
```

---

## Success Criteria

### Backend ✓

-  Server starts without errors
-  Authentication works
-  Database initialized
-  API endpoints respond
-  WebSocket connects
-  Packet capture works (with permissions)
-  Detection engine creates alerts
-  Correlation creates incidents
-  All tests pass

### Frontend ✓

-  Login page renders
-  Authentication flow works
-  Dashboard displays
-  Charts render
-  WebSocket receives updates
-  Alerts page functional
-  Incidents page functional
-  Modals work
-  No console errors

### Integration ✓

-  Real-time updates work
-  Alerts appear in dashboard
-  Incidents correlate correctly
-  Risk scores calculated
-  MITRE mapping works
-  Timeline generated
-  System responsive under load

---

## Next Steps

After successful testing:

1. **Deploy to Production**
   - Use Docker Compose
   - Configure production database
   - Set secure secrets
   - Enable HTTPS
   - Configure firewall
2. **Customize Detection Rules**
   - Edit YAML files in **`detection_rules/`**
   - Adjust thresholds
   - Add custom rules
3. **Configure Monitoring**
   - Set up log aggregation
   - Configure alerting
   - Monitor system health

---

## Support

**Issues Found?**

- Check logs: **`backend/logs/ids.log`**
- Browser console for frontend errors
- Backend terminal for API errors

**Common Issues:**

- Port 8000/3000 already in use
- Database connection failed
- Permission denied (packet capture)
- WebSocket connection refused
- CORS errors

**Solutions in troubleshooting section above.**

```
text
```


---
