#!/usr/bin/env python3
"""
ThreatLens AI — First Administrator Setup Script
Safely provisions or resets the initial administrator account from the CLI.
Does not expose any public web registration endpoints.
"""
import argparse
import getpass
import sys
import os
from sqlalchemy.engine import make_url

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import init_db, SessionLocal, normalize_database_url
from app.models import User
from app.services.auth_service import AuthService, ROLE_ADMIN
from app.config import settings

def bootstrap_admin(username: str, email: str, password: str, force: bool = False) -> bool:
    if not username or not username.strip():
        print("[!] Error: Administrator username cannot be empty.")
        return False

    if not email or "@" not in email:
        print("[!] Error: Administrator email must be a valid email address.")
        return False

    if not password or len(password.strip()) < 8:
        print("[!] Error: Administrator password must be at least 8 characters long.")
        return False

    # Display sanitized database connection target without leaking credentials
    try:
        norm_url = normalize_database_url(settings.DATABASE_URL)
        sanitized_url = make_url(norm_url).render_as_string(hide_password=True)
        print(f"[*] Target database: {sanitized_url}")
    except Exception:
        print("[*] Target database: [configured DATABASE_URL]")

    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter((User.username == username.strip()) | (User.email == email.strip())).first()
        if existing:
            if not force:
                print(f"[!] User with username '{username}' or email '{email}' already exists (ID: {existing.id}).")
                print("    Aborting. Use --force to explicitly reset this user's password.")
                return False
            existing.hashed_password = AuthService.hash_password(password.strip())
            existing.role = ROLE_ADMIN
            existing.is_active = True
            db.commit()
            print(f"[✓] Administrator account '{username}' successfully updated with new credentials.")
            return True
        else:
            admin_user = User(
                username=username.strip(),
                email=email.strip(),
                hashed_password=AuthService.hash_password(password.strip()),
                full_name="ThreatLens System Administrator",
                role=ROLE_ADMIN,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print(f"[✓] Initial administrator account '{username}' ({email}) successfully created.")
            return True
    except Exception as e:
        db.rollback()
        print(f"[!] Database error during administrator bootstrap: {e}")
        return False
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatLens AI — Production Administrator Bootstrap Utility")
    parser.add_argument("--username", default=settings.ADMIN_INITIAL_USERNAME, help="Admin username")
    parser.add_argument("--email", default=settings.ADMIN_INITIAL_EMAIL, help="Admin email")
    parser.add_argument("--password", default=None, help="Admin password (prompts securely if omitted)")
    parser.add_argument("--force", action="store_true", help="Force update existing admin password")
    args = parser.parse_args()

    pwd = args.password
    if not pwd:
        # Check environment variable fallback
        env_pwd = os.environ.get("ADMIN_PASSWORD") or os.environ.get("ADMIN_INITIAL_PASSWORD")
        if env_pwd and env_pwd.strip():
            pwd = env_pwd.strip()
        elif sys.stdin.isatty():
            pwd = getpass.getpass("Enter administrator password (min 8 chars): ")
        else:
            pwd = settings.ADMIN_INITIAL_PASSWORD

    success = bootstrap_admin(args.username, args.email, pwd, args.force)
    sys.exit(0 if success else 1)
