"""
Capture API endpoints
"""
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.api.deps import get_db, require_analyst
from app.models.user import User
from app.services.capture_service import capture_service
from app.services.audit_service import create_audit_log

router = APIRouter()


class CaptureStartRequest(BaseModel):
    """Capture start request"""
    interface: str
    bpf_filter: Optional[str] = None


class CaptureResponse(BaseModel):
    """Capture response"""
    status: str
    message: str


@router.post("/start", response_model=CaptureResponse)
def start_capture(
    *,
    db: Session = Depends(get_db),
    request: CaptureStartRequest,
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Start packet capture
    
    Requires analyst or admin role
    """
    try:
        success = capture_service.start_capture(
            db=db,
            interface=request.interface,
            bpf_filter=request.bpf_filter
        )
        
        if success:
            create_audit_log(
                db=db,
                user_id=current_user.id,
                username=current_user.username,
                action="capture_started",
                resource_type="capture",
                details={
                    "interface": request.interface,
                    "filter": request.bpf_filter
                },
                success=True
            )
            
            return {
                "status": "success",
                "message": f"Capture started on {request.interface}"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to start capture. Check permissions and interface."
            )
    
    except Exception as e:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            action="capture_start_failed",
            resource_type="capture",
            details={"error": str(e)},
            success=False
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/stop", response_model=CaptureResponse)
def stop_capture(
    *,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Stop packet capture
    
    Requires analyst or admin role
    """
    success = capture_service.stop_capture()
    
    if success:
        create_audit_log(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            action="capture_stopped",
            resource_type="capture",
            success=True
        )
        
        return {
            "status": "success",
            "message": "Capture stopped"
        }
    else:
        return {
            "status": "info",
            "message": "Capture was not running"
        }


@router.get("/status")
def get_capture_status(
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Get capture status and statistics
    """
    stats = capture_service.get_statistics()
    
    return {
        "is_running": capture_service.engine.is_running if capture_service.engine else False,
        "statistics": stats
    }


@router.get("/flows")
def get_active_flows(
    limit: int = 100,
    current_user: User = Depends(require_analyst)
) -> Any:
    """
    Get active flows from capture
    """
    flows = capture_service.get_active_flows(limit=limit)
    
    return {
        "count": len(flows),
        "flows": flows
    }
