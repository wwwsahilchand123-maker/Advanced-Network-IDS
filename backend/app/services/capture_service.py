"""
Capture service for managing packet capture operations
"""
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.capture.engine import CaptureEngine
from app.models.flow import Flow
from app.services.detection_service import detection_service
from app.core.logging import get_logger

logger = get_logger(__name__)


class CaptureService:
    """
    Service for managing network capture
    """
    
    def __init__(self):
        """Initialize capture service"""
        self.engine: Optional[CaptureEngine] = None
    
    def start_capture(
        self,
        db: Session,
        interface: str,
        bpf_filter: Optional[str] = None
    ) -> bool:
        """
        Start network capture
        
        Args:
            db: Database session
            interface: Network interface
            bpf_filter: Optional BPF filter
            
        Returns:
            True if started successfully
        """
        if self.engine and self.engine.is_running:
            logger.warning("Capture already running")
            return False
        
        # Initialize detection engine if not already done
        if not detection_service.engine:
            detection_service.initialize(db)
        
        def packet_callback(packet: Dict[str, Any], flow: Optional[Dict[str, Any]]):
            """Handle captured packet"""
            try:
                # Run detection
                alerts = detection_service.analyze_packet(packet, flow)
                
                # Store flow in database if significant
                if flow and flow.get("packet_count", 0) % 100 == 0:
                    self._store_flow(db, flow)
            
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
        
        self.engine = CaptureEngine(
            interface=interface,
            callback=packet_callback
        )
        
        if bpf_filter:
            self.engine.set_filter(bpf_filter)
        
        return self.engine.start()
    
    def stop_capture(self) -> bool:
        """
        Stop network capture
        
        Returns:
            True if stopped successfully
        """
        if not self.engine:
            return False
        
        return self.engine.stop()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get capture statistics
        
        Returns:
            Statistics dictionary
        """
        if not self.engine:
            return {}
        
        stats = self.engine.get_statistics()
        
        # Add detection statistics
        detection_stats = detection_service.get_statistics()
        stats["detection"] = detection_stats
        
        return stats
    
    def get_active_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get active flows
        
        Args:
            limit: Maximum number of flows
            
        Returns:
            List of flows
        """
        if not self.engine:
            return []
        
        return self.engine.get_active_flows(limit)
    
    def _store_flow(self, db: Session, flow_data: Dict[str, Any]) -> None:
        """
        Store or update flow in database
        
        Args:
            db: Database session
            flow_data: Flow data from tracker
        """
        try:
            flow = db.query(Flow).filter(
                Flow.src_ip == flow_data["src_ip"],
                Flow.dst_ip == flow_data["dst_ip"],
                Flow.src_port == flow_data["src_port"],
                Flow.dst_port == flow_data["dst_port"],
                Flow.protocol == flow_data["protocol"],
                Flow.first_seen >= datetime.utcnow() - timedelta(hours=1)
            ).first()
            
            if not flow:
                flow = Flow(
                    src_ip=flow_data["src_ip"],
                    dst_ip=flow_data["dst_ip"],
                    src_port=flow_data["src_port"],
                    dst_port=flow_data["dst_port"],
                    protocol=flow_data["protocol"],
                    src_mac=flow_data.get("src_mac"),
                    dst_mac=flow_data.get("dst_mac"),
                    first_seen=flow_data["first_seen"],
                    last_seen=flow_data["last_seen"],
                    packet_count=flow_data["packet_count"],
                    byte_count=flow_data["byte_count"],
                    tcp_flags=dict(flow_data.get("tcp_flags", {})),
                    state=flow_data["state"]
                )
                db.add(flow)
            else:
                flow.last_seen = flow_data["last_seen"]
                flow.packet_count = flow_data["packet_count"]
                flow.byte_count = flow_data["byte_count"]
                flow.tcp_flags = dict(flow_data.get("tcp_flags", {}))
                flow.state = flow_data["state"]
            
            db.commit()
        
        except Exception as e:
            logger.error(f"Error storing flow: {e}")
            db.rollback()


# Global capture service instance
capture_service = CaptureService()
