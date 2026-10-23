import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt

from app.config import settings
from app.database import Base
from app.main import app
from app.models import User, RefreshToken, Investigation
from app.services.auth_service import (
    AuthService,
    ROLE_ADMIN,
    ROLE_SENIOR_ANALYST,
    ROLE_READONLY_ANALYST
)
from app.database import bootstrap_first_admin
try:
    from tests.conftest import TestingSessionLocal, make_auth_headers
except ImportError:
    from backend.tests.conftest import TestingSessionLocal, make_auth_headers

client = TestClient(app)

def test_password_hashing():
    raw_pwd = "SecretPass123!"
    hashed = AuthService.hash_password(raw_pwd)
    assert hashed != raw_pwd
    assert hashed.startswith("$")
    assert AuthService.verify_password(raw_pwd, hashed) is True
    assert AuthService.verify_password("WrongPass123!", hashed) is False
    # Ensure salt uniqueness
    hashed2 = AuthService.hash_password(raw_pwd)
    assert hashed != hashed2
    assert AuthService.verify_password(raw_pwd, hashed2) is True

def test_login_success_and_no_hash_leak():
    db = TestingSessionLocal()
    user = User(
        username="login_success_user",
        email="login_success@threatlens.test",
        hashed_password=AuthService.hash_password("CorrectPass123!"),
        full_name="Success User",
        role=ROLE_SENIOR_ANALYST,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.close()

    res = client.post("/api/auth/login", json={
        "username": "login_success_user",
        "password": "CorrectPass123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "login_success_user"
    assert data["user"]["role"] == ROLE_SENIOR_ANALYST
    # Ensure password hash is not exposed
    assert "password_hash" not in str(data)
    assert "hashed_password" not in str(data)
    # Refresh token cookie must be set
    assert "threatlens_refresh_token" in res.cookies

def test_login_invalid_password():
    res = client.post("/api/auth/login", json={
        "username": "login_success_user",
        "password": "InvalidPassword999!"
    })
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()

def test_login_unknown_user():
    res = client.post("/api/auth/login", json={
        "username": "non_existent_user_99999",
        "password": "SomePassword123!"
    })
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()

def test_login_deactivated_user():
    db = TestingSessionLocal()
    deact_user = User(
        username="deactivated_analyst",
        email="deactivated@threatlens.test",
        hashed_password=AuthService.hash_password("DeactPass123!"),
        role=ROLE_READONLY_ANALYST,
        is_active=False
    )
    db.add(deact_user)
    db.commit()
    db.close()

    res = client.post("/api/auth/login", json={
        "username": "deactivated_analyst",
        "password": "DeactPass123!"
    })
    assert res.status_code == 403
    assert "deactivated" in res.json()["detail"].lower()

def test_current_user_me_endpoint():
    headers = make_auth_headers(ROLE_SENIOR_ANALYST)
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == ROLE_SENIOR_ANALYST
    assert "hashed_password" not in data

def test_invalid_and_expired_access_tokens():
    # 1. Invalid signature
    tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJhZG1pbiJ9.invalid_signature"
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401

    # 2. Expired access token
    db = TestingSessionLocal()
    user = User(
        username="expired_token_user",
        email="expired@threatlens.test",
        hashed_password=AuthService.hash_password("TestPass123!"),
        role=ROLE_SENIOR_ANALYST,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    expired_token = AuthService.create_access_token(user, expires_delta=timedelta(seconds=-10))
    db.close()

    res2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res2.status_code == 401
    assert "expired" in res2.json()["detail"].lower()

    # 3. Wrong token type (e.g. type != access)
    payload = {"sub": user.id, "username": user.username, "type": "refresh", "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}
    wrong_type_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    res3 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {wrong_type_token}"})
    assert res3.status_code == 401

def test_refresh_token_rotation_and_revocation():
    db = TestingSessionLocal()
    rot_user = User(
        username="refresh_test_user",
        email="refresh_test@threatlens.test",
        hashed_password=AuthService.hash_password("Pass123!"),
        role=ROLE_SENIOR_ANALYST,
        is_active=True
    )
    db.add(rot_user)
    db.commit()
    db.refresh(rot_user)

    rot_user_id = rot_user.id
    raw_refresh = AuthService.create_refresh_token(db, rot_user)
    db.close()

    # 1. Refresh using valid token
    client.cookies.set("threatlens_refresh_token", raw_refresh)
    res = client.post("/api/auth/refresh")
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["username"] == "refresh_test_user"
    new_refresh = res.cookies.get("threatlens_refresh_token")
    assert new_refresh is not None
    assert new_refresh != raw_refresh

    # 2. Replay attack attempt: Using the previous (now revoked) refresh token must fail with 401
    client.cookies.set("threatlens_refresh_token", raw_refresh)
    res_replay = client.post("/api/auth/refresh")
    assert res_replay.status_code == 401
    assert "revoked" in res_replay.json()["detail"].lower()

    # 3. Expired refresh token
    db = TestingSessionLocal()
    expired_raw = "expired_test_refresh_token_abc123"
    expired_db_token = RefreshToken(
        user_id=rot_user_id,
        token_hash=AuthService.hash_token(expired_raw),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_revoked=False
    )
    db.add(expired_db_token)
    db.commit()
    db.close()

    client.cookies.set("threatlens_refresh_token", expired_raw)
    res_exp = client.post("/api/auth/refresh")
    assert res_exp.status_code == 401
    assert "expired" in res_exp.json()["detail"].lower()

def test_logout_revokes_token_and_clears_cookie():
    db = TestingSessionLocal()
    logout_user = User(
        username="logout_user_test",
        email="logout@threatlens.test",
        hashed_password=AuthService.hash_password("Pass123!"),
        role=ROLE_READONLY_ANALYST,
        is_active=True
    )
    db.add(logout_user)
    db.commit()
    db.refresh(logout_user)
    raw_refresh = AuthService.create_refresh_token(db, logout_user)
    db.close()

    client.cookies.set("threatlens_refresh_token", raw_refresh)
    res = client.post("/api/auth/logout")
    assert res.status_code == 200
    assert res.json()["message"] == "Successfully logged out."

    # Confirm token is revoked in DB
    db = TestingSessionLocal()
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == AuthService.hash_token(raw_refresh)).first()
    assert db_token.is_revoked is True
    db.close()

    # Refresh attempt must now fail
    client.cookies.set("threatlens_refresh_token", raw_refresh)
    res2 = client.post("/api/auth/refresh")
    assert res2.status_code == 401

def test_unauthenticated_requests_blocked():
    unauth_client = TestClient(app)
    # Protected endpoints must reject unauthenticated requests
    assert unauth_client.get("/api/auth/me").status_code == 401
    assert unauth_client.get("/api/investigations").status_code == 401
    assert unauth_client.post("/api/investigate", json={"indicator": "8.8.8.8"}).status_code == 401
    assert unauth_client.get("/api/dashboard/stats").status_code == 401
    assert unauth_client.post("/api/bulk/triage", json={"items": []}).status_code == 401
    assert unauth_client.get("/api/users").status_code == 401

def test_role_permissions_admin():
    admin_headers = make_auth_headers(ROLE_ADMIN)

    # Admin can list users
    res_list = client.get("/api/users", headers=admin_headers)
    assert res_list.status_code == 200
    assert "users" in res_list.json()

    # Admin can create a new user
    new_user_data = {
        "username": "new_analyst_created_by_admin",
        "email": "new_analyst@threatlens.test",
        "password": "TemporaryPass123!",
        "full_name": "New Analyst",
        "role": ROLE_SENIOR_ANALYST
    }
    res_create = client.post("/api/users", json=new_user_data, headers=admin_headers)
    assert res_create.status_code == 201
    created = res_create.json()
    assert created["username"] == "new_analyst_created_by_admin"
    assert created["role"] == ROLE_SENIOR_ANALYST
    user_id = created["id"]

    # Admin can update user role
    res_patch = client.patch(f"/api/users/{user_id}", json={"role": ROLE_READONLY_ANALYST}, headers=admin_headers)
    assert res_patch.status_code == 200
    assert res_patch.json()["role"] == ROLE_READONLY_ANALYST

    # Admin can delete user
    res_del = client.delete(f"/api/users/{user_id}", headers=admin_headers)
    assert res_del.status_code == 200

def test_role_permissions_senior_analyst():
    senior_headers = make_auth_headers(ROLE_SENIOR_ANALYST)

    # Can run investigation
    inv_res = client.post("/api/investigate", json={"indicator": "1.1.1.1", "indicator_type": "ipv4"}, headers=senior_headers)
    assert inv_res.status_code in [200, 201]

    # Can view history and stats
    assert client.get("/api/investigations", headers=senior_headers).status_code == 200
    assert client.get("/api/dashboard/stats", headers=senior_headers).status_code == 200

    # CANNOT manage users (403 Forbidden)
    assert client.get("/api/users", headers=senior_headers).status_code == 403
    assert client.post("/api/users", json={}, headers=senior_headers).status_code == 403

def test_role_permissions_readonly_analyst():
    ro_headers = make_auth_headers(ROLE_READONLY_ANALYST)

    # Can view history and stats
    assert client.get("/api/investigations", headers=ro_headers).status_code == 200
    assert client.get("/api/dashboard/stats", headers=ro_headers).status_code == 200

    # CANNOT initiate investigation (403 Forbidden)
    inv_res = client.post("/api/investigate", json={"indicator": "8.8.8.8", "indicator_type": "ipv4"}, headers=ro_headers)
    assert inv_res.status_code == 403

    # CANNOT run bulk triage (403 Forbidden)
    bulk_res = client.post("/api/bulk/triage", json={"items": [{"indicator": "8.8.8.8"}]}, headers=ro_headers)
    assert bulk_res.status_code == 403

    # CANNOT access user management (403 Forbidden)
    assert client.get("/api/users", headers=ro_headers).status_code == 403

def test_privilege_escalation_prevented():
    senior_headers = make_auth_headers(ROLE_SENIOR_ANALYST)
    ro_headers = make_auth_headers(ROLE_READONLY_ANALYST)

    # Non-admin cannot promote user to admin
    assert client.patch("/api/users/some-user-id", json={"role": ROLE_ADMIN}, headers=senior_headers).status_code == 403
    assert client.patch("/api/users/some-user-id", json={"role": ROLE_ADMIN}, headers=ro_headers).status_code == 403

    # Non-admin cannot register admin user
    assert client.post("/api/users", json={"username": "evil_admin", "password": "p", "role": ROLE_ADMIN}, headers=ro_headers).status_code == 403

def test_safe_administrator_bootstrap():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    # 1. Test bootstrap on an empty database creates admin
    fresh_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=fresh_engine)
    FreshSession = sessionmaker(autocommit=False, autoflush=False, bind=fresh_engine)
    fresh_db = FreshSession()

    assert fresh_db.query(User).count() == 0
    created_admin = bootstrap_first_admin(fresh_db)
    assert created_admin is not None
    assert fresh_db.query(User).count() == 1
    assert created_admin.username == settings.ADMIN_INITIAL_USERNAME
    assert created_admin.role == ROLE_ADMIN

    # 2. Subsequent runs are idempotent / no-op
    second_run = bootstrap_first_admin(fresh_db)
    assert second_run is None
    assert fresh_db.query(User).count() == 1
    fresh_db.close()
