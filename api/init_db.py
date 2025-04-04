import asyncio
from database import engine, Base
from models import Setting, Alert, OCSFLog  # Include OCSFLog model

async def init():
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    asyncio.run(init())