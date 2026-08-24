"""
Create admin user
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.session import SessionLocal
from app.models.user import User
from app.core.security import get_password_hash
from app.core.config import settings
from app.core.logging import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


def create_admin_user():
    """Create admin user from settings"""
    db = SessionLocal()
    
    try:
        # Check if admin exists
        admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        
        if admin:
            logger.warning(f"Admin user '{settings.ADMIN_USERNAME}' already exists")
            return
        
        # Create admin user
        admin = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            password_hash=get_password_hash(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True
        )
        
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        logger.info(f"Admin user created successfully!")
        logger.info(f"Username: {admin.username}")
        logger.info(f"Email: {admin.email}")
        logger.warning(f"Please change the default password immediately!")
        
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    create_admin_user()
