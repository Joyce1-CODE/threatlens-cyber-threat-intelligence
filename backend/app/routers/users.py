from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserResponse, UserCreateRequest, UserUpdateRequest, UserListResponse
from app.services.auth_service import AuthService, require_admin, VALID_ROLES, ROLE_ADMIN

router = APIRouter(prefix="/users", tags=["User Management"])

@router.get("", response_model=UserListResponse)
def list_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return UserListResponse(
        total=len(users),
        users=[UserResponse.model_validate(u) for u in users]
    )

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{payload.role}'. Must be one of: {', '.join(VALID_ROLES)}"
        )

    existing = db.query(User).filter(
        (User.username == payload.username.strip()) | (User.email == payload.email.strip().lower())
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username or email already exists."
        )

    new_user = User(
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        hashed_password=AuthService.hash_password(payload.password),
        full_name=payload.full_name or "",
        role=payload.role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserResponse.model_validate(new_user)

@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' was not found."
        )

    if payload.role is not None:
        if payload.role not in VALID_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role '{payload.role}'. Must be one of: {', '.join(VALID_ROLES)}"
            )
        # Prevent demoting the last active administrator
        if user.role == ROLE_ADMIN and payload.role != ROLE_ADMIN:
            admin_count = db.query(User).filter(User.role == ROLE_ADMIN, User.is_active == True).count()
            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the last remaining active administrator."
                )
        user.role = payload.role

    if payload.is_active is not None:
        # Prevent deactivating self or the last active administrator
        if user.id == admin.id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate your own administrator account."
            )
        if user.role == ROLE_ADMIN and not payload.is_active:
            admin_count = db.query(User).filter(User.role == ROLE_ADMIN, User.is_active == True).count()
            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the last remaining active administrator."
                )
        user.is_active = payload.is_active

    if payload.full_name is not None:
        user.full_name = payload.full_name

    if payload.password:
        user.hashed_password = AuthService.hash_password(payload.password)

    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)

@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def delete_user(
    user_id: str,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own administrator account."
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' was not found."
        )

    if user.role == ROLE_ADMIN:
        admin_count = db.query(User).filter(User.role == ROLE_ADMIN, User.is_active == True).count()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last remaining active administrator."
            )

    db.delete(user)
    db.commit()
    return {"status": "deleted", "id": user_id}
