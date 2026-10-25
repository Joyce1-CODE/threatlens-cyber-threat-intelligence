from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

def normalize_database_url(url: str) -> str:
    """
    Normalizes database URLs for SQLAlchemy compatibility.
    - Converts legacy 'postgres://' (Render/Heroku) to 'postgresql+psycopg2://'
    - Converts unadorned 'postgresql://' to 'postgresql+psycopg2://' so that
      SQLAlchemy loads the installed psycopg2 driver instead of searching for psycopg (v3).
    - Preserves explicitly specified drivers (e.g. 'postgresql+psycopg2://', 'postgresql+asyncpg://')
    - Preserves SQLite and other database URLs unchanged.
    """
    if not url:
        return "sqlite:///./threatlens.db"
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url

# Normalize database URL
db_url = normalize_database_url(settings.DATABASE_URL)

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
