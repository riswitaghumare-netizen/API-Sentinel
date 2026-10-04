from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import settings

# Determine DB connection string
database_url = settings.DATABASE_URL
if settings.POSTGRES_SERVER and settings.POSTGRES_USER and settings.POSTGRES_PASSWORD and settings.POSTGRES_DB:
    database_url = f"postgresql+asyncpg://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_SERVER}/{settings.POSTGRES_DB}"

# SQLite specific connect args
connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}

engine = create_async_engine(
    database_url,
    echo=False,
    future=True,
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Creates all database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
