import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.main import app
from app.core.database import Base, get_db
from app.core.security import create_access_token, get_password_hash
from app.core.rbac import Role
from app.models.user import User
from app.models.organization import Organization, Project

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DB_URL, echo=False, future=True)
TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with TestAsyncSessionLocal() as session:
        yield session
        await session.rollback()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def admin_auth_headers(db_session: AsyncSession) -> dict:
    org = Organization(name="Test Org", slug="test-org")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Test Project", slug="test-proj")
    db_session.add(proj)
    await db_session.flush()

    admin = User(
        email="testadmin@sentinel.sec",
        hashed_password=get_password_hash("TestPass123!"),
        full_name="Test SuperAdmin",
        role=Role.SUPER_ADMIN,
        organization_id=org.id,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    token = create_access_token(subject=admin.id, role=admin.role.value, org_id=org.id)
    return {"Authorization": f"Bearer {token}", "X-Org-Id": org.id, "X-Project-Id": proj.id}
