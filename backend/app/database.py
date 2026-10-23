from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

# Normalize database URL (handles Render / Heroku / Supabase postgres:// prefix)
db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Configure engine kwargs based on dialect
engine_kwargs = {"echo": False}
if db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Production PostgreSQL connection pooling & keepalive
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    engine_kwargs["pool_recycle"] = 300

engine = create_engine(db_url, **engine_kwargs)

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
