from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, RefreshTokenRequest, AuthTokenResponse, UserResponse
from app.services.auth_service import AuthService, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

COOKIE_NAME = "threatlens_refresh_token"

def extract_refresh_token(request: Request, payload: Optional[RefreshTokenRequest] = None) -> Optional[str]:
    """Extract refresh token from cookie, JSON body, or custom header."""
    token = request.cookies.get(COOKIE_NAME)
    if not token and payload and payload.refresh_token:
        token = payload.refresh_token
    if not token:
        token = request.headers.get("X-Refresh-Token")
    return token

@router.post("/login", response_model=AuthTokenResponse)
def login(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    # Support login with either username or email
    user = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.username)
    ).first()

    if not user or not AuthService.verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Contact an administrator."
        )

    access_token = AuthService.create_access_token(user)
    refresh_token = AuthService.create_refresh_token(db, user)

    # Secure HTTP-only cookie for refresh token
    response.set_cookie(
        key=COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
        path="/api/auth"
    )

    return AuthTokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
        refresh_token=refresh_token
    )

@router.post("/refresh", response_model=AuthTokenResponse)
def refresh_token_endpoint(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db)
):
    raw_token = extract_refresh_token(request, payload)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing from cookie or request body."
        )

    user, new_access, new_refresh = AuthService.rotate_refresh_token(db, raw_token)

    response.set_cookie(
        key=COOKIE_NAME,
        value=new_refresh,
        httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE.lower(),
        path="/api/auth"
    )

    return AuthTokenResponse(
        access_token=new_access,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
        refresh_token=new_refresh
    )

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db)
):
    raw_token = extract_refresh_token(request, payload)
    if raw_token:
        AuthService.revoke_refresh_token(db, raw_token)

    response.delete_cookie(
        key=COOKIE_NAME,
        path="/api/auth",
        samesite=settings.COOKIE_SAMESITE.lower(),
        secure=settings.COOKIE_SECURE
    )
    return {"status": "success", "message": "Successfully logged out."}

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)

@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    """Safe public health diagnostic endpoint to verify auth initialization without exposing secrets."""
    user_count = db.query(User).count()
    admin_count = db.query(User).filter(User.role == "Admin").count()
    return {
        "initialized": user_count > 0,
        "admin_configured": admin_count > 0,
        "user_count": user_count,
        "cookie_secure": settings.COOKIE_SECURE,
        "cookie_samesite": settings.COOKIE_SAMESITE.lower(),
        "cors_origins_count": len(settings.CORS_ORIGINS),
    }
