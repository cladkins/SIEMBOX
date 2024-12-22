import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine
from database import Base, DATABASE_URL
from models import Log, Setting, Alert  # Import all models to ensure they're registered

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def init_db():
    try:
        logger.info("Creating database engine...")
        engine = create_async_engine(
            DATABASE_URL,
            echo=True
        )
        
        logger.info("Creating database tables...")
        async with engine.begin() as conn:
            # Drop existing tables
            logger.info("Dropping existing tables...")
            await conn.run_sync(Base.metadata.drop_all)
            
            # Create new tables
            logger.info("Creating new tables...")
            await conn.run_sync(Base.metadata.create_all)
            
            # Verify table creation
            logger.info("Verifying table creation...")
            await conn.run_sync(lambda sync_conn: logger.info(f"Created tables: {Base.metadata.tables.keys()}"))
        
        logger.info("Database initialization completed successfully!")
        
        # Close engine
        await engine.dispose()
        logger.info("Database connection closed.")
        
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")
        raise

def run_async_init():
    try:
        logger.info("Starting database initialization...")
        asyncio.run(init_db())
        logger.info("Database initialization completed.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

if __name__ == "__main__":
    run_async_init()