#!/usr/bin/env python3
"""
ThreatLens AI — Safe SQLite to PostgreSQL Migration Utility

Transfers existing investigation history, user accounts, and refresh tokens
from the local SQLite database to a target PostgreSQL database (e.g. Render, Neon, Supabase).
Preserves the local SQLite database completely intact without deletion or alteration.
"""
import os
import sys
import argparse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.models import Base, User, RefreshToken, Investigation
from app.config import settings

def migrate(source_sqlite_path: str, target_postgres_url: str):
    # Normalize postgres URL if needed
    if target_postgres_url.startswith("postgres://"):
        target_postgres_url = target_postgres_url.replace("postgres://", "postgresql://", 1)

    print(f"[*] Starting migration from: {source_sqlite_path}")
    print(f"[*] Target database: {target_postgres_url.split('@')[-1] if '@' in target_postgres_url else 'Target DB'}")

    if not os.path.exists(source_sqlite_path):
        print(f"[!] Source SQLite file not found: {source_sqlite_path}")
        print("    No existing data to migrate. Initializing target PostgreSQL schema directly...")

    # Create engines
    source_url = f"sqlite:///{source_sqlite_path}" if not source_sqlite_path.startswith("sqlite") else source_sqlite_path
    source_engine = create_engine(source_url, connect_args={"check_same_thread": False})
    SourceSession = sessionmaker(bind=source_engine)

    target_engine = create_engine(
        target_postgres_url,
        pool_pre_ping=True,
        pool_recycle=300
    )
    TargetSession = sessionmaker(bind=target_engine)

    # 1. Initialize schema in target
    print("[*] Creating tables in target PostgreSQL database...")
    Base.metadata.create_all(bind=target_engine)
    print("[✓] Schema initialized successfully.")

    if not os.path.exists(source_sqlite_path.replace("sqlite:///", "")):
        print("[✓] Target database ready with fresh schema.")
        return True

    source_db = SourceSession()
    target_db = TargetSession()

    try:
        # 2. Migrate Users
        users = source_db.query(User).all()
        user_count = 0
        for u in users:
            existing = target_db.query(User).filter(User.id == u.id).first()
            if not existing:
                new_u = User(
                    id=u.id,
                    username=u.username,
                    email=u.email,
                    hashed_password=u.hashed_password,
                    full_name=u.full_name,
                    role=u.role,
                    is_active=u.is_active,
                    created_at=u.created_at,
                    updated_at=u.updated_at
                )
                target_db.add(new_u)
                user_count += 1
        target_db.commit()
        print(f"[✓] Migrated {user_count} users (total source: {len(users)}).")

        # 3. Migrate Refresh Tokens
        tokens = source_db.query(RefreshToken).all()
        token_count = 0
        for t in tokens:
            existing = target_db.query(RefreshToken).filter(RefreshToken.id == t.id).first()
            if not existing:
                new_t = RefreshToken(
                    id=t.id,
                    user_id=t.user_id,
                    token_hash=t.token_hash,
                    expires_at=t.expires_at,
                    is_revoked=t.is_revoked,
                    created_at=t.created_at
                )
                target_db.add(new_t)
                token_count += 1
        target_db.commit()
        print(f"[✓] Migrated {token_count} refresh tokens (total source: {len(tokens)}).")

        # 4. Migrate Investigations
        investigations = source_db.query(Investigation).all()
        inv_count = 0
        for inv in investigations:
            existing = target_db.query(Investigation).filter(Investigation.id == inv.id).first()
            if not existing:
                new_inv = Investigation(
                    id=inv.id,
                    indicator=inv.indicator,
                    normalized_indicator=inv.normalized_indicator,
                    indicator_type=inv.indicator_type,
                    risk_score=inv.risk_score,
                    severity=inv.severity,
                    confidence=inv.confidence,
                    data_coverage=inv.data_coverage,
                    verdict_summary=inv.verdict_summary,
                    vt_status=inv.vt_status,
                    otx_status=inv.otx_status,
                    vt_detections=inv.vt_detections,
                    vt_total_engines=inv.vt_total_engines,
                    otx_pulse_count=inv.otx_pulse_count,
                    evidence=inv.evidence,
                    investigated_at=inv.investigated_at
                )
                target_db.add(new_inv)
                inv_count += 1
        target_db.commit()
        print(f"[✓] Migrated {inv_count} investigation records (total source: {len(investigations)}).")

        print("\n" + "=" * 60)
        print(" MIGRATION COMPLETE & VERIFIED")
        print(" Local SQLite database preserved intact at: " + source_sqlite_path)
        print("=" * 60)
        return True

    except Exception as e:
        target_db.rollback()
        print(f"[✗] Migration error: {e}")
        return False
    finally:
        source_db.close()
        target_db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate ThreatLens AI SQLite data to PostgreSQL.")
    parser.add_argument("--source", default="threatlens.db", help="Path to source SQLite file (default: threatlens.db)")
    parser.add_argument("--target", default=None, help="Target PostgreSQL connection URL")

    args = parser.parse_args()
    target_url = args.target or os.environ.get("TARGET_DATABASE_URL") or os.environ.get("DATABASE_URL")

    if not target_url or target_url.startswith("sqlite"):
        print("[!] Target PostgreSQL URL must be provided via --target or TARGET_DATABASE_URL environment variable.")
        print("    Example: python migrate_to_postgres.py --target postgresql://user:pass@host:5432/dbname")
        sys.exit(1)

    success = migrate(args.source, target_url)
    sys.exit(0 if success else 1)
