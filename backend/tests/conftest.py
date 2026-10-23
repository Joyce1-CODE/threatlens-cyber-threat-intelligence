import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import User
from app.services.auth_service import AuthService, ROLE_ADMIN, ROLE_SENIOR_ANALYST, ROLE_READONLY_ANALYST

# In-memory SQLite for testing with StaticPool so all threads/sessions share the same DB
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create all tables (investigations, users, refresh_tokens)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="session")
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_or_get_user(db, role: str, username: str = None) -> User:
    if username is None:
        slug = role.lower().replace(" ", "_").replace("-", "_")
        username = f"test_{slug}"
    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            email=f"{username}@threatlens.test",
            hashed_password=AuthService.hash_password("TestPass123!"),
            full_name=f"Test {role}",
            role=role,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user

def make_auth_headers(role: str = ROLE_SENIOR_ANALYST) -> dict:
    db = TestingSessionLocal()
    user = create_or_get_user(db, role)
    token = AuthService.create_access_token(user)
    db.close()
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_admin(db_session):
    return make_auth_headers(ROLE_ADMIN)

@pytest.fixture
def auth_headers_senior(db_session):
    return make_auth_headers(ROLE_SENIOR_ANALYST)

@pytest.fixture
def auth_headers_readonly(db_session):
    return make_auth_headers(ROLE_READONLY_ANALYST)
