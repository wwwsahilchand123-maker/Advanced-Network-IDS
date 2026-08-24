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
