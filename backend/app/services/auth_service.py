import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import User, RefreshToken

# Security bearer scheme
security_bearer = HTTPBearer(auto_error=False)

# Roles constants
ROLE_ADMIN = "Admin"
ROLE_SENIOR_ANALYST = "Senior Analyst"
ROLE_READONLY_ANALYST = "Read-Only Analyst"

VALID_ROLES = [ROLE_ADMIN, ROLE_SENIOR_ANALYST, ROLE_READONLY_ANALYST]

class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a plaintext password using bcrypt with 12 rounds."""
        pwd_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(pwd_bytes, salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify plain password against bcrypt hash."""
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False

    @staticmethod
    def hash_token(token: str) -> str:
        """Create SHA256 digest of refresh token for safe database persistence."""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    @staticmethod
    def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
        """Issue short-lived JWT access token."""
        delta = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        now = datetime.now(timezone.utc)
        expire = now + delta
        payload = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "type": "access"
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    @staticmethod
    def decode_access_token(token: str) -> dict:
        """Decode and validate JWT access token."""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            if payload.get("type") != "access":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type."
                )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token has expired."
            )
        except (jwt.InvalidTokenError, Exception):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials."
            )

    @staticmethod
    def create_refresh_token(db: Session, user: User) -> str:
        """Generate a cryptographically secure refresh token and store hash in DB."""
        raw_token = secrets.token_urlsafe(48)
        token_hash = AuthService.hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        db_token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            is_revoked=False
        )
        db.add(db_token)
        db.commit()
        return raw_token

    @staticmethod
    def rotate_refresh_token(db: Session, raw_token: str) -> tuple[User, str, str]:
        """Verify, revoke old token, issue new refresh token & access token."""
        token_hash = AuthService.hash_token(raw_token)
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

        if not db_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token."
            )

        if db_token.is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked."
            )

        now = datetime.now(timezone.utc)
        token_exp = db_token.expires_at
        if token_exp.tzinfo is None:
            token_exp = token_exp.replace(tzinfo=timezone.utc)

        if token_exp < now:
            db_token.is_revoked = True
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired."
            )

        # Revoke old token
        db_token.is_revoked = True

        user = db.query(User).filter(User.id == db_token.user_id).first()
        if not user or not user.is_active:
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account inactive or not found."
            )

        # Generate new pair
        new_refresh = AuthService.create_refresh_token(db, user)
        new_access = AuthService.create_access_token(user)
        return user, new_access, new_refresh

    @staticmethod
    def revoke_refresh_token(db: Session, raw_token: str) -> bool:
        """Mark refresh token as revoked."""
        if not raw_token:
            return False
        token_hash = AuthService.hash_token(raw_token)
        db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if db_token:
            db_token.is_revoked = True
            db.commit()
            return True
        return False

# Dependency to retrieve current user from Bearer token
def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = AuthService.decode_access_token(auth.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject identifier."
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    return user

# Factory for role-based authorization
def require_roles(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{current_user.role}' lacks permission for this action."
            )
        return current_user
    return role_checker

# Shortcuts
require_admin = require_roles([ROLE_ADMIN])
require_analyst = require_roles([ROLE_ADMIN, ROLE_SENIOR_ANALYST])
require_authenticated = require_roles([ROLE_ADMIN, ROLE_SENIOR_ANALYST, ROLE_READONLY_ANALYST])
