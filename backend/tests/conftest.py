import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set environment variables for testing before loading anything else
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["REDIS_URL"] = ""
os.environ["JWT_SECRET_KEY"] = "testaccesssecretkey"
os.environ["JWT_REFRESH_SECRET_KEY"] = "testrefreshsecretkey"
os.environ["MTD_ROTATION_INTERVAL_SECONDS"] = "2"  # Make it fast for tests
os.environ["TESTING"] = "1"

from app.main import app
from app.core.database import Base
from app.utils.deps import get_db

# Configure test SQLite db
TEST_DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _clear_in_memory_state():
    """Reset all singleton in-memory state that should not leak between tests."""
    # Clear IP block cache
    from app.services.threat_mitigation import threat_mitigation_service
    threat_mitigation_service._blocked_cache.clear()

    # Clear honeypot telemetry log (used for window counting)
    from app.services.mtd_service import mtd_service
    mtd_service.honeypot_logs.clear()


@pytest.fixture(scope="function", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)

    # Seed default roles and permissions for RBAC enforcement in tests
    from app.models.rbac import Role, Permission
    from app.core.rbac import ROLE_PERMISSIONS
    seed_db = TestingSessionLocal()
    try:
        for role_name, perms in ROLE_PERMISSIONS.items():
            role = Role(name=role_name)
            seed_db.add(role)
            seed_db.commit()
            seed_db.refresh(role)
            for p_name in perms:
                perm = seed_db.query(Permission).filter(Permission.name == p_name).first()
                if not perm:
                    perm = Permission(name=p_name)
                    seed_db.add(perm)
                    seed_db.commit()
                    seed_db.refresh(perm)
                role.permissions.append(perm)
        seed_db.commit()
    finally:
        seed_db.close()

    # ── Redirect all direct SessionLocal() calls in middleware / services
    #    to use the test database so there is no cross-contamination between
    #    the test DB and app.db during HTTP-level tests.
    import app.core.database as db_module
    original_session_local = db_module.SessionLocal
    db_module.SessionLocal = TestingSessionLocal

    yield

    # Restore original SessionLocal
    db_module.SessionLocal = original_session_local

    Base.metadata.drop_all(bind=engine)
    engine.dispose()

    # Clear in-memory singletons so they don't bleed into the next test
    _clear_in_memory_state()

    # Remove test db file
    if os.path.exists("./test.db"):
        try:
            os.remove("./test.db")
        except (PermissionError, Exception):
            pass


@pytest.fixture(scope="function")
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
