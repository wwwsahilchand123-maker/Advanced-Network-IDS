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
