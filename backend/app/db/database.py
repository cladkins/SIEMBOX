"""
SIEM BOX - Database Connection and Session Management
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Create async SQLAlchemy engine
engine = create_async_engine(
    settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
    echo=settings.database_echo,
    pool_pre_ping=True,
    pool_recycle=300
)

# Create AsyncSessionLocal class
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Create Base class for models
Base = declarative_base()


async def get_db():
    """
    Async dependency to get database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """
    Initialize database tables and create default admin user
    """
    try:
        # Import models to ensure they are registered with Base
        from app.models import logs, users
        
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
        
        # Create default admin user
        from app.services.auth_service import AuthService
        async with AsyncSessionLocal() as session:
            try:
                await AuthService.create_default_admin(session)
            except Exception as e:
                logger.error(f"Failed to create default admin: {e}")
                # Don't raise here as this is not critical for startup
                
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise