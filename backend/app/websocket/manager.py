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
