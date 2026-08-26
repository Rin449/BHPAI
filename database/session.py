import os
from typing import Optional, AsyncGenerator, Any

try:
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from sqlalchemy.orm import DeclarativeBase
    SQLALCHEMY_AVAILABLE = True

    class Base(DeclarativeBase):
        pass

except Exception:
    SQLALCHEMY_AVAILABLE = False
    AsyncSession = Any
    class Base:
        pass

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://bhpai:bhpai@localhost:5432/bhpai")

engine = None
async_session: Optional[Any] = None

if SQLALCHEMY_AVAILABLE:
    try:
        engine = create_async_engine(DATABASE_URL, future=True, echo=False)
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    except Exception:
        pass

async def get_db_session() -> AsyncGenerator[Any, None]:
    if async_session is None:
        raise RuntimeError("Database session factory is not initialized")
    async with async_session() as session:
        yield session
