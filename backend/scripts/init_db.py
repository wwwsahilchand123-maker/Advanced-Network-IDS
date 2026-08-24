"""
Initialize database with tables and initial data
"""
import sys
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db.session import engine
from app.db.base import Base
from app.core.logging import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


def init_db():
    """Initialize database tables"""
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully!")


if __name__ == "__main__":
    init_db()
