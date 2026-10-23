from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

# SQLite specific connect_args to allow multithreading safely
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Import all models to register with Base
    from app.models import Investigation, User, RefreshToken
    Base.metadata.create_all(bind=engine)

    # Safe administrator bootstrap (only runs if zero users exist)
    bootstrap_first_admin()

def bootstrap_first_admin(session=None):
    from app.models import User
    from app.services.auth_service import AuthService, ROLE_ADMIN

    db = session or SessionLocal()
    should_close = session is None
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            initial_admin = User(
                username=settings.ADMIN_INITIAL_USERNAME,
                email=settings.ADMIN_INITIAL_EMAIL,
                hashed_password=AuthService.hash_password(settings.ADMIN_INITIAL_PASSWORD),
                full_name="ThreatLens System Administrator",
                role=ROLE_ADMIN,
                is_active=True
            )
            db.add(initial_admin)
            db.commit()
            print(f"[BOOTSTRAP] Initial administrator account created: '{settings.ADMIN_INITIAL_USERNAME}'")
            return initial_admin
        return None
    except Exception as e:
        db.rollback()
        print(f"[BOOTSTRAP WARNING] Could not bootstrap admin: {e}")
        return None
    finally:
        if should_close:
            db.close()
