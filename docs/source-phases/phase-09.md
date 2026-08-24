# PHASE 7: WebSocket & Real-Time Updates

Building the WebSocket server for real-time dashboard updates and live event streaming.

---

## 📁 File 87: `backend/app/websocket/__init__.py`

```
Python
```

```
"""
WebSocket module initialization
"""
```

---

## 📁 File 88: `backend/app/websocket/manager.py`

```
Python
```

```
"""
WebSocket Connection Manager
Manages WebSocket connections and broadcasts
"""
from typing import Dict, Set, Any, Optional
from fastapi import WebSocket
from datetime import datetime
import asyncio
import json

from app.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections and message broadcasting
    """
    
    def __init__(self):
        """Initialize connection manager"""
        # Active connections: user_id -> set of WebSocket connections
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        
        # Anonymous connections (not authenticated)
        self.anonymous_connections: Set[WebSocket] = set()
        
        # Statistics
        self.total_connections = 0
        self.messages_sent = 0
        
        logger.info("WebSocket Connection Manager initialized")
    
    async def connect(
        self,
        websocket: WebSocket,
        user_id: Optional[int] = None
    ) -> None:
        """
        Accept and register a new WebSocket connection
        
        Args:
            websocket: WebSocket connection
            user_id: User ID if authenticated
        """
        await websocket.accept()
        
        if user_id:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = set()
            self.active_connections[user_id].add(websocket)
            logger.info(f"WebSocket connected: user_id={user_id}")
        else:
            self.anonymous_connections.add(websocket)
            logger.info("Anonymous WebSocket connected")
        
        self.total_connections += 1
        
        # Send welcome message
        await self.send_personal_message(
            websocket,
            {
                "type": "connection_established",
                "message": "Connected to IDS WebSocket",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    def disconnect(self, websocket: WebSocket, user_id: Optional[int] = None):
        """
        Remove a WebSocket connection
        
        Args:
            websocket: WebSocket connection to remove
            user_id: User ID if authenticated
        """
        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            logger.info(f"WebSocket disconnected: user_id={user_id}")
        else:
            self.anonymous_connections.discard(websocket)
            logger.info("Anonymous WebSocket disconnected")
    
    async def send_personal_message(
        self,
        websocket: WebSocket,
        message: Dict[str, Any]
    ) -> None:
        """
        Send message to specific WebSocket connection
        
        Args:
            websocket: Target WebSocket
            message: Message dictionary
        """
        try:
            await websocket.send_json(message)
            self.messages_sent += 1
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
    
    async def send_to_user(self, user_id: int, message: Dict[str, Any]) -> None:
        """
        Send message to all connections of a specific user
        
        Args:
            user_id: Target user ID
            message: Message dictionary
        """
        if user_id in self.active_connections:
            disconnected = set()
            
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                    self.messages_sent += 1
                except Exception as e:
                    logger.error(f"Error sending to user {user_id}: {e}")
                    disconnected.add(connection)
            
            # Clean up disconnected
            for connection in disconnected:
                self.active_connections[user_id].discard(connection)
    
    async def broadcast(
        self,
        message: Dict[str, Any],
        exclude_user: Optional[int] = None
    ) -> None:
        """
        Broadcast message to all connected clients
        
        Args:
            message: Message dictionary
            exclude_user: Optional user ID to exclude from broadcast
        """
        disconnected_users = set()
        disconnected_anonymous = set()
        
        # Broadcast to authenticated users
        for user_id, connections in self.active_connections.items():
            if exclude_user and user_id == exclude_user:
                continue
            
            disconnected = set()
            for connection in connections:
                try:
                    await connection.send_json(message)
                    self.messages_sent += 1
                except Exception as e:
                    logger.error(f"Error broadcasting to user {user_id}: {e}")
                    disconnected.add(connection)
            
            # Track disconnected
            for connection in disconnected:
                connections.discard(connection)
            
            if not connections:
                disconnected_users.add(user_id)
        
        # Clean up empty user sets
        for user_id in disconnected_users:
            del self.active_connections[user_id]
        
        # Broadcast to anonymous connections
        for connection in self.anonymous_connections:
            try:
                await connection.send_json(message)
                self.messages_sent += 1
            except Exception as e:
                logger.error(f"Error broadcasting to anonymous: {e}")
                disconnected_anonymous.add(connection)
        
        # Clean up disconnected anonymous
        self.anonymous_connections -= disconnected_anonymous
    
    async def broadcast_alert(self, alert: Dict[str, Any]) -> None:
        """
        Broadcast new alert to all connections
        
        Args:
            alert: Alert data
        """
        message = {
            "type": "new_alert",
            "data": alert,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.broadcast(message)
        logger.debug(f"Alert broadcasted: {alert.get('title')}")
    
    async def broadcast_incident(self, incident: Dict[str, Any]) -> None:
        """
        Broadcast new/updated incident
        
        Args:
            incident: Incident data
        """
        message = {
            "type": "incident_update",
            "data": incident,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.broadcast(message)
        logger.debug(f"Incident broadcasted: {incident.get('title')}")
    
    async def broadcast_stats_update(self, stats: Dict[str, Any]) -> None:
        """
        Broadcast dashboard statistics update
        
        Args:
            stats: Statistics data
        """
        message = {
            "type": "stats_update",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.broadcast(message)
    
    async def broadcast_flow_update(self, flows: list) -> None:
        """
        Broadcast flow updates
        
        Args:
            flows: List of flow data
        """
        message = {
            "type": "flow_update",
            "data": flows,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.broadcast(message)
    
    async def broadcast_system_message(
        self,
        message_text: str,
        level: str = "info"
    ) -> None:
        """
        Broadcast system message to all clients
        
        Args:
            message_text: Message text
            level: Message level (info, warning, error)
        """
        message = {
            "type": "system_message",
            "level": level,
            "message": message_text,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.broadcast(message)
    
    def get_connection_count(self) -> Dict[str, int]:
        """
        Get connection statistics
        
        Returns:
            Connection statistics
        """
        authenticated = sum(len(conns) for conns in self.active_connections.values())
        anonymous = len(self.anonymous_connections)
        
        return {
            "authenticated": authenticated,
            "anonymous": anonymous,
            "total": authenticated + anonymous,
            "total_lifetime": self.total_connections,
            "messages_sent": self.messages_sent,
        }


# Global connection manager instance
manager = ConnectionManager()
```

---

## 📁 File 89: `backend/app/websocket/events.py`

```
Python
```

```
"""
WebSocket Event Handlers
Background tasks for periodic updates
"""
import asyncio
from typing import Optional
from datetime import datetime

from app.websocket.manager import manager
from app.services.capture_service import capture_service
from app.services.detection_service import detection_service
from app.core.logging import get_logger

logger = get_logger(__name__)


class WebSocketEventBroadcaster:
    """
    Broadcasts periodic updates to WebSocket clients
    """
    
    def __init__(self):
        """Initialize broadcaster"""
        self.running = False
        self.task: Optional[asyncio.Task] = None
        
        # Update intervals (seconds)
        self.stats_interval = 5  # Dashboard stats every 5 seconds
        self.flow_interval = 10  # Flow updates every 10 seconds
    
    async def start(self):
        """Start periodic broadcasting"""
        if self.running:
            logger.warning("WebSocket broadcaster already running")
            return
        
        self.running = True
        self.task = asyncio.create_task(self._broadcast_loop())
        logger.info("WebSocket broadcaster started")
    
    async def stop(self):
        """Stop periodic broadcasting"""
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("WebSocket broadcaster stopped")
    
    async def _broadcast_loop(self):
        """Main broadcast loop"""
        stats_counter = 0
        flow_counter = 0
        
        try:
            while self.running:
                await asyncio.sleep(1)
                
                stats_counter += 1
                flow_counter += 1
                
                # Broadcast stats update
                if stats_counter >= self.stats_interval:
                    await self._broadcast_stats()
                    stats_counter = 0
                
                # Broadcast flow update
                if flow_counter >= self.flow_interval:
                    await self._broadcast_flows()
                    flow_counter = 0
        
        except asyncio.CancelledError:
            logger.info("Broadcast loop cancelled")
        except Exception as e:
            logger.error(f"Error in broadcast loop: {e}", exc_info=True)
    
    async def _broadcast_stats(self):
        """Broadcast dashboard statistics"""
        try:
            # Get capture statistics
            capture_stats = capture_service.get_statistics()
            
            # Get detection statistics
            detection_stats = detection_service.get_statistics()
            
            # Combine stats
            stats = {
                "capture": {
                    "packets_analyzed": capture_stats.get("total_packets", 0),
                    "total_bytes": capture_stats.get("total_bytes", 0),
                    "packets_per_second": capture_stats.get("packets_per_second", 0),
                    "active_flows": capture_stats.get("flow_stats", {}).get("active_flows", 0),
                },
                "detection": detection_stats,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            await manager.broadcast_stats_update(stats)
        
        except Exception as e:
            logger.error(f"Error broadcasting stats: {e}")
    
    async def _broadcast_flows(self):
        """Broadcast active flow updates"""
        try:
            # Get top active flows
            flows = capture_service.get_active_flows(limit=20)
            
            # Format for frontend
            flow_data = []
            for flow in flows:
                flow_data.append({
                    "src_ip": flow.get("src_ip"),
                    "dst_ip": flow.get("dst_ip"),
                    "src_port": flow.get("src_port"),
                    "dst_port": flow.get("dst_port"),
                    "protocol": flow.get("protocol"),
                    "packet_count": flow.get("packet_count"),
                    "byte_count": flow.get("byte_count"),
                    "state": flow.get("state"),
                })
            
            await manager.broadcast_flow_update(flow_data)
        
        except Exception as e:
            logger.error(f"Error broadcasting flows: {e}")


# Global broadcaster instance
broadcaster = WebSocketEventBroadcaster()
```

---

## 📁 File 90: `backend/app/api/websocket.py`

```
Python
```

```
"""
WebSocket API Endpoints
Real-time event streaming
"""
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from jose import JWTError

from app.websocket.manager import manager
from app.core.security import decode_token
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


async def get_current_user_ws(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
) -> Optional[int]:
    """
    Get current user from WebSocket token
    
    Args:
        websocket: WebSocket connection
        token: JWT token from query parameter
        
    Returns:
        User ID or None if not authenticated
    """
    if not token:
        return None
    
    try:
        payload = decode_token(token)
        user_id: int = payload.get("sub")
        return user_id
    except JWTError:
        logger.warning("Invalid WebSocket token")
        return None


@router.websocket("/events")
async def websocket_events(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time event streaming
    
    Connect with: ws://localhost:8000/api/v1/ws/events?token=YOUR_JWT_TOKEN
    
    Events broadcast:
    - new_alert: New security alert
    - incident_update: Incident created/updated
    - stats_update: Dashboard statistics
    - flow_update: Active network flows
    - system_message: System notifications
    """
    # Get user ID if authenticated
    user_id = await get_current_user_ws(websocket, token)
    
    # Connect
    await manager.connect(websocket, user_id)
    
    try:
        # Keep connection alive and handle incoming messages
        while True:
            # Receive message (for heartbeat/ping)
            data = await websocket.receive_text()
            
            # Handle ping/pong
            if data == "ping":
                await manager.send_personal_message(
                    websocket,
                    {"type": "pong", "timestamp": datetime.utcnow().isoformat()}
                )
            
            # Handle other client messages if needed
            # For now, this is primarily a server->client channel
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
        logger.info(f"WebSocket disconnected: user_id={user_id}")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        manager.disconnect(websocket, user_id)


@router.websocket("/dashboard")
async def websocket_dashboard(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint specifically for dashboard real-time updates
    
    Connect with: ws://localhost:8000/api/v1/ws/dashboard?token=YOUR_JWT_TOKEN
    
    Receives:
    - stats_update: Every 5 seconds
    - flow_update: Every 10 seconds
    - new_alert: When alert generated
    """
    user_id = await get_current_user_ws(websocket, token)
    
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            data = await websocket.receive_text()
            
            if data == "ping":
                await manager.send_personal_message(
                    websocket,
                    {"type": "pong"}
                )
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
    
    except Exception as e:
        logger.error(f"Dashboard WebSocket error: {e}")
        manager.disconnect(websocket, user_id)


@router.get("/connections")
async def get_websocket_connections():
    """
    Get WebSocket connection statistics
    
    Admin endpoint to monitor active connections
    """
    return manager.get_connection_count()
```

---

## 📁 File 91: `backend/app/services/detection_service.py` (Updated with WebSocket)

```
Python
```

```
"""
Detection service for managing detection engine
Now broadcasts alerts via WebSocket
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine
from app.services.incident_service import incident_service
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.core.config import settings
from app.core.logging import get_logger

# Import WebSocket manager
from app.websocket.manager import manager as ws_manager

logger = get_logger(__name__)


class DetectionService:
    """
    Service for managing detection engine and correlation
    """
    
    def __init__(self):
        """Initialize detection service"""
        self.engine: Optional[DetectionEngine] = None
        self.correlation_engine: Optional[CorrelationEngine] = None
        self._db = None
    
    def initialize(self, db: Session) -> bool:
        """
        Initialize detection engine and correlation
        
        Args:
            db: Database session
            
        Returns:
            True if initialized successfully
        """
        try:
            self._db = db
            
            # Alert callback: stores alert, broadcasts via WebSocket, then correlates
            def alert_callback(alert_data: Dict[str, Any]):
                try:
                    stored = self._store_alert(db, alert_data)
                    
                    if stored:
                        # Attach DB ID for incident linking
                        alert_data["id"] = stored.id
                        
                        # Broadcast via WebSocket (async call from sync context)
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                asyncio.create_task(
                                    ws_manager.broadcast_alert(self._format_alert_for_ws(stored))
                                )
                            else:
                                loop.run_until_complete(
                                    ws_manager.broadcast_alert(self._format_alert_for_ws(stored))
                                )
                        except Exception as e:
                            logger.error(f"Error broadcasting alert via WebSocket: {e}")
                        
                        # Send to correlation engine
                        if self.correlation_engine:
                            incident = self.correlation_engine.process_alert(alert_data)
                            
                            if incident:
                                stored_incident = incident_service.store_incident(db, incident)
                                
                                # Broadcast incident via WebSocket
                                if stored_incident:
                                    try:
                                        loop = asyncio.get_event_loop()
                                        if loop.is_running():
                                            asyncio.create_task(
                                                ws_manager.broadcast_incident(
                                                    self._format_incident_for_ws(stored_incident)
                                                )
                                            )
                                    except Exception as e:
                                        logger.error(f"Error broadcasting incident: {e}")
                
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}", exc_info=True)
            
            # Initialize detection engine
            self.engine = DetectionEngine(alert_callback=alert_callback)
            
            # Load rules
            self._load_rules_from_db(db)
            self.engine.load_rules(settings.DETECTION_RULES_PATH)
            
            # Initialize correlation engine
            def incident_callback(incident: Dict[str, Any], action: str):
                """Callback when incident created/updated"""
                try:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    
                    message = {
                        "incident": incident,
                        "action": action,  # created, updated, escalated
                    }
                    
                    if loop.is_running():
                        asyncio.create_task(ws_manager.broadcast_incident(message))
                except Exception as e:
                    logger.error(f"Error in incident callback: {e}")
            
            self.correlation_engine = CorrelationEngine(incident_callback=incident_callback)
            
            logger.info("Detection and correlation engines initialized")
            return True
        
        except Exception as e:
            logger.error(f"Error initializing detection service: {e}", exc_info=True)
            return False
    
    def analyze_packet(
        self,
        packet: Dict[str, Any],
        flow: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze packet for threats (includes correlation and WebSocket broadcast)
        
        Args:
            packet: Parsed packet data
            flow: Associated flow data
            
        Returns:
            List of generated alerts
        """
        if not self.engine:
            return []
        
        return self.engine.analyze_packet(packet, flow)
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection and correlation statistics
        
        Returns:
            Statistics dictionary
        """
        stats = {}
        
        if self.engine:
            stats["detection"] = self.engine.get_statistics()
        
        if self.correlation_engine:
            stats["correlation"] = self.correlation_engine.get_statistics()
        
        return stats
    
    def _load_rules_from_db(self, db: Session) -> None:
        """Load rules from database"""
        try:
            if self.engine:
                count = self.engine.rule_manager.load_rules_from_database(db)
                logger.info(f"Loaded {count} rules from database")
        except Exception as e:
            logger.error(f"Error loading rules from database: {e}")
    
    def _store_alert(self, db: Session, alert_data: Dict[str, Any]) -> Optional[Alert]:
        """
        Store alert in database
        
        Args:
            db: Database session
            alert_data: Alert data
            
        Returns:
            Stored alert or None
        """
        try:
            alert = Alert(
                rule_id=alert_data.get("rule_id"),
                title=alert_data["title"],
                description=alert_data.get("description"),
                category=alert_data.get("category"),
                severity=alert_data["severity"],
                confidence=alert_data.get("confidence"),
                src_ip=alert_data.get("src_ip"),
                dst_ip=alert_data.get("dst_ip"),
                src_port=alert_data.get("src_port"),
                dst_port=alert_data.get("dst_port"),
                protocol=alert_data.get("protocol"),
                evidence=alert_data.get("evidence"),
                mitre_attack_id=alert_data.get("mitre_attack_id"),
                timestamp=alert_data.get("timestamp", datetime.utcnow()),
                status="new"
            )
            
            db.add(alert)
            db.commit()
            db.refresh(alert)
            
            logger.info(f"Alert stored: {alert.title} ({alert.severity})")
            return alert
        
        except Exception as e:
            logger.error(f"Error storing alert: {e}", exc_info=True)
            db.rollback()
            return None
    
    def _format_alert_for_ws(self, alert: Alert) -> Dict[str, Any]:
        """Format alert for WebSocket broadcast"""
        return {
            "id": alert.id,
            "alert_uuid": alert.alert_uuid,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "category": alert.category,
            "confidence": alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol,
            "timestamp": alert.timestamp.isoformat(),
            "status": alert.status,
        }
    
    def _format_incident_for_ws(self, incident) -> Dict[str, Any]:
        """Format incident for WebSocket broadcast"""
        return {
            "id": incident.id,
            "incident_uuid": incident.incident_uuid,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "src_ip": incident.src_ip,
            "alert_count": incident.alert_count,
            "first_seen": incident.first_seen.isoformat(),
            "last_seen": incident.last_seen.isoformat(),
        }


# Global detection service instance
detection_service = DetectionService()
```

---

## 📁 File 92: `backend/app/main.py` (Updated with WebSocket)

```
Python
```

```
"""
Main FastAPI application with WebSocket support
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api import auth, capture, alerts, incidents, dashboard
from app.api import websocket as ws
from app.websocket.events import broadcaster

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    
    # Start WebSocket broadcaster
    await broadcaster.start()
    logger.info("WebSocket broadcaster started")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    await broadcaster.stop()
    logger.info("WebSocket broadcaster stopped")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced Network Intrusion Detection System - Production-Grade SOC Platform",
    lifespan=lifespan,
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json"
)

# CORS middleware - Allow WebSocket connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include HTTP routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_PREFIX}/auth",
    tags=["Authentication"]
)

app.include_router(
    capture.router,
    prefix=f"{settings.API_V1_PREFIX}/capture",
    tags=["Capture"]
)

app.include_router(
    alerts.router,
    prefix=f"{settings.API_V1_PREFIX}/alerts",
    tags=["Alerts"]
)

app.include_router(
    incidents.router,
    prefix=f"{settings.API_V1_PREFIX}/incidents",
    tags=["Incidents"]
)

app.include_router(
    dashboard.router,
    prefix=f"{settings.API_V1_PREFIX}/dashboard",
    tags=["Dashboard"]
)

# Include WebSocket router
app.include_router(
    ws.router,
    prefix=f"{settings.API_V1_PREFIX}/ws",
    tags=["WebSocket"]
)


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "description": "Advanced Network Intrusion Detection System",
        "websocket_url": f"ws://localhost:8000{settings.API_V1_PREFIX}/ws/events"
    }


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "websocket_enabled": True
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
```

---

## 📁 File 93: `backend/tests/test_websocket/test_websocket.py`

```
Python
```

```
"""
Tests for WebSocket functionality
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_websocket_connection(client):
    """Test WebSocket connection without auth"""
    with client.websocket_connect("/api/v1/ws/events") as websocket:
        # Should receive welcome message
        data = websocket.receive_json()
        assert data["type"] == "connection_established"
        assert "timestamp" in data


def test_websocket_ping_pong(client):
    """Test WebSocket ping/pong"""
    with client.websocket_connect("/api/v1/ws/events") as websocket:
        # Skip welcome message
        websocket.receive_json()
        
        # Send ping
        websocket.send_text("ping")
        
        # Should receive pong
        data = websocket.receive_json()
        assert data["type"] == "pong"


def test_websocket_dashboard_connection(client):
    """Test dashboard WebSocket endpoint"""
    with client.websocket_connect("/api/v1/ws/dashboard") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "connection_established"
```

---

## 📁 File 94: `backend/websocket_client_example.py`

```
Python
```

```
"""
Example WebSocket Client
For testing real-time event streaming
"""
import asyncio
import websockets
import json


async def listen_to_events():
    """
    Connect to IDS WebSocket and listen for events
    """
    # For authenticated connection, append token:
    # uri = "ws://localhost:8000/api/v1/ws/events?token=YOUR_JWT_TOKEN"
    uri = "ws://localhost:8000/api/v1/ws/events"
    
    async with websockets.connect(uri) as websocket:
        print(f"Connected to {uri}")
        
        # Send ping every 30 seconds
        async def ping_loop():
            while True:
                await asyncio.sleep(30)
                await websocket.send("ping")
                print("Sent ping")
        
        # Start ping task
        ping_task = asyncio.create_task(ping_loop())
        
        try:
            # Listen for messages
            async for message in websocket:
                data = json.loads(message)
                
                event_type = data.get("type")
                
                if event_type == "connection_established":
                    print("✓ Connection established")
                
                elif event_type == "new_alert":
                    alert = data["data"]
                    print(f"\n🚨 NEW ALERT:")
                    print(f"   Title: {alert['title']}")
                    print(f"   Severity: {alert['severity']}")
                    print(f"   Source: {alert.get('src_ip')}")
                    print(f"   Time: {alert['timestamp']}")
                
                elif event_type == "incident_update":
                    incident = data["data"]
                    print(f"\n🔴 INCIDENT UPDATE:")
                    print(f"   Title: {incident.get('title')}")
                    print(f"   Risk Score: {incident.get('risk_score')}")
                    print(f"   Severity: {incident.get('severity')}")
                
                elif event_type == "stats_update":
                    stats = data["data"]
                    capture = stats.get("capture", {})
                    print(f"\n📊 Stats: Packets={capture.get('packets_analyzed', 0)}, "
                          f"Flows={capture.get('active_flows', 0)}")
                
                elif event_type == "flow_update":
                    flows = data["data"]
                    print(f"\n🌐 Flow Update: {len(flows)} active flows")
                
                elif event_type == "pong":
                    print("Received pong")
        
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            ping_task.cancel()


if __name__ == "__main__":
    print("IDS WebSocket Client")
    print("Connecting to real-time event stream...")
    print("Press Ctrl+C to exit\n")
    
    asyncio.run(listen_to_events())
```

---

## 📁 File 95: `README.md` (Updated with WebSocket info)

```
Markdown
```

````
# Advanced Network Intrusion Detection System (IDS)

A production-grade, real-time network intrusion detection and monitoring system built for SOC environments.

## 🚀 Features

### Core Detection
- **Real-time Packet Capture** - Scapy-based network traffic analysis
- **Flow-Based Tracking** - 5-tuple flow aggregation and statistics
- **Multi-Stage Detection Engine** - 6 specialized threat detectors
  - Port scan detection (vertical & horizontal)
  - Brute force detection (SSH, FTP, RDP, HTTP)
  - ARP spoofing detection
  - DNS anomaly detection (DGA, tunneling, excessive queries)
  - Traffic anomaly detection (baseline-based)
  - Suspicious traffic patterns

### Advanced Analysis
- **Event Correlation** - Multi-event incident creation with attack chain detection
- **Transparent Risk Scoring** - 6-component explainable risk calculation (0-100)
- **MITRE ATT&CK Mapping** - Verified technique identification
- **Attack Chain Detection** - 4 predefined kill chain patterns

### Real-Time Capabilities
- **WebSocket Support** - Live event streaming to connected clients
- **Real-Time Dashboards** - Auto-updating statistics and metrics
- **Live Alert Feed** - Instant security event notifications
- **Flow Updates** - Active network connection monitoring

### SOC Features
- **Alert Management** - Complete lifecycle with analyst workflow
- **Incident Investigation** - Correlated events with timeline visualization
- **Role-Based Access Control** - Admin, Analyst, and Viewer roles
- **Audit Logging** - Complete security event trail
- **PCAP Analysis** - Upload and analyze capture files offline

## 📡 WebSocket Real-Time Updates

### Event Types

Connect to: `ws://localhost:8000/api/v1/ws/events?token=YOUR_JWT_TOKEN`

**Broadcasted Events:**
- `new_alert` - Security alert generated
- `incident_update` - Incident created/updated
- `stats_update` - Dashboard statistics (every 5s)
- `flow_update` - Active flows (every 10s)
- `system_message` - System notifications

### Example Client

```python
import websockets
import asyncio
import json

async def listen():
    uri = "ws://localhost:8000/api/v1/ws/events"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            data = json.loads(message)
            print(f"{data['type']}: {data['data']}")

asyncio.run(listen())
````

## 🛠️ Technology Stack

**Backend:**

- Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL
- Scapy (packet capture), Redis (caching)
- WebSocket support for real-time updates

**Frontend:** (Coming in Phase 10)

- React + TypeScript, Tailwind CSS, Recharts

## 📦 Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+ (optional, for caching)
- Root/admin privileges (for packet capture)

### Setup

```
Bash
```

```
# Clone repository
git clone https://github.com/yourusername/advanced-ids.git
cd advanced-ids

# Install dependencies
cd backend
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Initialize database
python scripts/init_db.py
alembic upgrade head

# Create admin user
python scripts/create_admin.py

# Run server
uvicorn app.main:app --reload
```

## 🔌 API Endpoints

### Authentication

- **`POST /api/v1/auth/login`** - Login
- **`POST /api/v1/auth/register`** - Register
- **`GET /api/v1/auth/me`** - Current user

### Capture

- **`POST /api/v1/capture/start`** - Start capture
- **`POST /api/v1/capture/stop`** - Stop capture
- **`GET /api/v1/capture/status`** - Capture status

### Alerts

- **`GET /api/v1/alerts/`** - List alerts (with filtering)
- **`GET /api/v1/alerts/{id}`** - Get alert details
- **`PATCH /api/v1/alerts/{id}`** - Update alert
- **`POST /api/v1/alerts/{id}/acknowledge`** - Acknowledge
- **`GET /api/v1/alerts/stats`** - Statistics

### Incidents

- **`GET /api/v1/incidents/`** - List incidents
- **`GET /api/v1/incidents/{id}`** - Get details
- **`PATCH /api/v1/incidents/{id}`** - Update
- **`POST /api/v1/incidents/{id}/escalate`** - Escalate
- **`POST /api/v1/incidents/{id}/resolve`** - Resolve

### Dashboard

- **`GET /api/v1/dashboard/stats`** - Main statistics
- **`GET /api/v1/dashboard/traffic-over-time`** - Traffic charts
- **`GET /api/v1/dashboard/protocol-distribution`** - Protocol breakdown
- **`GET /api/v1/dashboard/top-sources`** - Top source IPs
- **`GET /api/v1/dashboard/alert-trends`** - Alert trends

### WebSocket

- **`WS /api/v1/ws/events`** - Real-time event stream
- **`WS /api/v1/ws/dashboard`** - Dashboard updates
- **`GET /api/v1/ws/connections`** - Connection stats

## 🧪 Testing

```
Bash
```

```
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Test WebSocket
python websocket_client_example.py
```

## 📊 Current Progress

**Completed (Backend \~80%):**

- ✅ Authentication & RBAC
- ✅ Packet capture engine
- ✅ 6 threat detectors
- ✅ Event correlation
- ✅ Risk scoring
- ✅ Alert/Incident APIs
- ✅ WebSocket real-time updates
- ✅ Dashboard statistics

**Remaining:**

- ⏳ PCAP upload API
- ⏳ Report generation
- ⏳ Demo mode
- ⏳ Frontend UI (React)

## 🔐 Security

- Bcrypt password hashing (cost factor: 12)
- JWT authentication with refresh tokens
- Role-based access control
- Input validation (Pydantic)
- SQL injection prevention (ORM)
- Audit logging
- No payload storage (metadata only)

## ⚠️ Disclaimer

This tool is for **authorized security testing and monitoring only**. Use only on networks you own or have explicit permission to monitor.

## 📄 License

MIT License

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

```
text
```

````

---

## ✅ PHASE 7 COMPLETE

**Implemented:**
- ✅ WebSocket Connection Manager
  - User authentication support
  - Connection lifecycle management
  - Personal messaging
  - Broadcast to all clients
  - Broadcast to specific users

- ✅ Event Broadcasting System
  - New alerts broadcast
  - Incident updates broadcast
  - Dashboard stats broadcast (every 5s)
  - Flow updates broadcast (every 10s)
  - System messages

- ✅ WebSocket API Endpoints
  - `/ws/events` - General event stream
  - `/ws/dashboard` - Dashboard-specific updates
  - Connection statistics endpoint

- ✅ Background Broadcasting
  - Periodic stats updates
  - Automatic flow updates
  - Async event loop integration

- ✅ Integration with Detection Engine
  - Alerts auto-broadcast on detection
  - Incidents auto-broadcast on correlation
  - Real-time event streaming

- ✅ WebSocket Client Example
  - Python example client
  - Event type handling
  - Ping/pong heartbeat

**Testing WebSocket:**

```bash
# Terminal 1: Start server
cd backend
make dev

# Terminal 2: Run example WebSocket client
python websocket_client_example.py

# Terminal 3: Generate test traffic (or start capture)
curl -X POST http://localhost:8000/api/v1/capture/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface": "lo"}'

# You should see real-time events in Terminal 2!
````

**Backend Progress: \~82% Complete**

**Remaining Backend (Phases 8-9): \~18%**

- PCAP upload/analysis API
- Report generation (PDF/CSV)
- Rules management API
- User management API
- Demo mode

**Ab kya karein?**

Reply with:

- **"PHASE 8"** - Continue with remaining backend APIs
- **"FRONTEND"** - Jump to React dashboard (recommended!)
- **"DEMO"** - Build demo mode first