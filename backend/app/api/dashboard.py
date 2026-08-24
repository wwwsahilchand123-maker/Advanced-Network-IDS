"""
Dashboard API
Real-time SOC dashboard statistics and visualizations
"""
from typing import Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from collections import defaultdict

from app.api.deps import get_db, require_viewer
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.flow import Flow
from app.models.user import User
from app.schemas.dashboard import DashboardData, DashboardStats
from app.services.capture_service import capture_service
from app.services.detection_service import detection_service
from app.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Get main dashboard statistics
    """
    # Get capture statistics
    capture_stats = capture_service.get_statistics()
    
    # Alert statistics (last 24 hours)
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    alerts_today = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= cutoff_24h
    ).scalar() or 0
    
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= cutoff_24h,
        Alert.severity == "CRITICAL"
    ).scalar() or 0
    
    # High risk sources (IPs with multiple alerts)
    high_risk_query = db.query(
        Alert.src_ip,
        func.count(Alert.id).label("count")
    ).filter(
        Alert.timestamp >= cutoff_24h,
        Alert.src_ip.isnot(None)
    ).group_by(Alert.src_ip).having(
        func.count(Alert.id) >= 5
    ).all()
    
    high_risk_sources = len(high_risk_query)
    
    # Events per second (from capture)
    events_per_second = capture_stats.get("packets_per_second", 0.0)
    
    return {
        "packets_analyzed": capture_stats.get("total_packets", 0),
        "active_flows": capture_stats.get("flow_stats", {}).get("active_flows", 0),
        "alerts_today": alerts_today,
        "critical_alerts": critical_alerts,
        "high_risk_sources": high_risk_sources,
        "total_bytes": capture_stats.get("total_bytes", 0),
        "events_per_second": round(events_per_second, 2),
    }


@router.get("/traffic-over-time")
def get_traffic_over_time(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(30, ge=5, le=120),
) -> Any:
    """
    Get traffic volume over time for charts
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    # Query flows grouped by time interval
    flows = db.query(Flow).filter(
        Flow.first_seen >= cutoff
    ).all()
    
    # Group by time buckets
    time_buckets = defaultdict(lambda: {"packets": 0, "bytes": 0})
    
    for flow in flows:
        # Round to interval
        bucket_time = flow.first_seen.replace(
            minute=(flow.first_seen.minute // interval_minutes) * interval_minutes,
            second=0,
            microsecond=0
        )
        
        time_buckets[bucket_time]["packets"] += flow.packet_count
        time_buckets[bucket_time]["bytes"] += flow.byte_count
    
    # Sort and format
    data = []
    for timestamp in sorted(time_buckets.keys()):
        data.append({
            "timestamp": timestamp.isoformat(),
            "packets": time_buckets[timestamp]["packets"],
            "bytes": time_buckets[timestamp]["bytes"],
        })
    
    return {
        "interval_minutes": interval_minutes,
        "data": data
    }


@router.get("/protocol-distribution")
def get_protocol_distribution(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
) -> Any:
    """
    Get protocol distribution for pie/donut charts
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    # Get capture statistics
    capture_stats = capture_service.get_statistics()
    protocol_stats = capture_stats.get("packets_by_protocol", {})
    
    total_packets = sum(protocol_stats.values())
    
    distribution = []
    for protocol, count in sorted(
        protocol_stats.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        distribution.append({
            "protocol": protocol,
            "count": count,
            "percentage": round(percentage, 2)
        })
    
    return {
        "total_packets": total_packets,
        "distribution": distribution
    }


@router.get("/top-sources")
def get_top_sources(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
) -> Any:
    """
    Get top source IPs by packet/alert count
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    # Aggregate from flows
    sources = db.query(
        Flow.src_ip,
        func.sum(Flow.packet_count).label("packets"),
        func.sum(Flow.byte_count).label("bytes"),
        func.count(Flow.id).label("flow_count")
    ).filter(
        Flow.first_seen >= cutoff
    ).group_by(Flow.src_ip).order_by(
        desc("packets")
    ).limit(limit).all()
    
    # Get alert counts for each source
    result = []
    for src_ip, packets, bytes_total, flow_count in sources:
        alert_count = db.query(func.count(Alert.id)).filter(
            Alert.src_ip == src_ip,
            Alert.timestamp >= cutoff
        ).scalar() or 0
        
        # Calculate basic risk score
        risk_score = min(100, (alert_count * 10) + (flow_count // 10))
        
        result.append({
            "ip_address": src_ip,
            "packets": packets,
            "bytes": bytes_total,
            "flow_count": flow_count,
            "alert_count": alert_count,
            "risk_score": risk_score,
        })
    
    return {"sources": result}


@router.get("/top-destinations")
def get_top_destinations(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
) -> Any:
    """
    Get top destination IPs
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    destinations = db.query(
        Flow.dst_ip,
        func.sum(Flow.packet_count).label("packets"),
        func.sum(Flow.byte_count).label("bytes"),
        func.count(Flow.id).label("flow_count")
    ).filter(
        Flow.first_seen >= cutoff
    ).group_by(Flow.dst_ip).order_by(
        desc("packets")
    ).limit(limit).all()
    
    result = []
    for dst_ip, packets, bytes_total, flow_count in destinations:
        result.append({
            "ip_address": dst_ip,
            "packets": packets,
            "bytes": bytes_total,
            "flow_count": flow_count,
        })
    
    return {"destinations": result}


@router.get("/top-ports")
def get_top_ports(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
) -> Any:
    """
    Get most commonly contacted ports
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    ports = db.query(
        Flow.dst_port,
        Flow.protocol,
        func.count(Flow.id).label("count")
    ).filter(
        Flow.first_seen >= cutoff,
        Flow.dst_port.isnot(None)
    ).group_by(Flow.dst_port, Flow.protocol).order_by(
        desc("count")
    ).limit(limit).all()
    
    result = []
    for port, protocol, count in ports:
        result.append({
            "port": port,
            "protocol": protocol,
            "count": count,
        })
    
    return {"ports": result}


@router.get("/alert-trends")
def get_alert_trends(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(60, ge=5, le=120),
) -> Any:
    """
    Get alert trends over time by severity
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    alerts = db.query(Alert).filter(
        Alert.timestamp >= cutoff
    ).all()
    
    # Group by time and severity
    time_buckets = defaultdict(lambda: defaultdict(int))
    
    for alert in alerts:
        bucket_time = alert.timestamp.replace(
            minute=(alert.timestamp.minute // interval_minutes) * interval_minutes,
            second=0,
            microsecond=0
        )
        time_buckets[bucket_time][alert.severity] += 1
    
    # Format for charts
    trends = []
    for timestamp in sorted(time_buckets.keys()):
        trends.append({
            "timestamp": timestamp.isoformat(),
            "INFO": time_buckets[timestamp].get("INFO", 0),
            "LOW": time_buckets[timestamp].get("LOW", 0),
            "MEDIUM": time_buckets[timestamp].get("MEDIUM", 0),
            "HIGH": time_buckets[timestamp].get("HIGH", 0),
            "CRITICAL": time_buckets[timestamp].get("CRITICAL", 0),
        })
    
    return {"trends": trends}


@router.get("/recent-events")
def get_recent_events(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
    limit: int = Query(50, ge=1, le=200),
) -> Any:
    """
    Get recent security events for live feed
    """
    alerts = db.query(Alert).order_by(
        desc(Alert.timestamp)
    ).limit(limit).all()
    
    events = []
    for alert in alerts:
        events.append({
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity,
            "title": alert.title,
            "category": alert.category,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "confidence": alert.confidence,
            "status": alert.status,
        })
    
    return {"events": events}


@router.get("/system-health")
def get_system_health(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Get system health status
    """
    # Capture engine status
    capture_running = capture_service.engine.is_running if capture_service.engine else False
    
    # Detection engine status
    detection_stats = detection_service.get_statistics()
    detection_running = detection_service.engine is not None
    
    # Database connection
    try:
        db.execute("SELECT 1")
        db_healthy = True
    except:
        db_healthy = False
    
    return {
        "capture_engine": "running" if capture_running else "stopped",
        "detection_engine": "running" if detection_running else "stopped",
        "database": "healthy" if db_healthy else "error",
        "overall_status": "healthy" if (capture_running and detection_running and db_healthy) else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
    }
