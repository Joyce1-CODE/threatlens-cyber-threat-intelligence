#!/usr/bin/env python3
"""
ThreatLens AI — First Administrator Setup Script
Safely provisions or resets the initial administrator account from the CLI.
Does not expose any public web registration endpoints.
"""
import argparse
import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import init_db, SessionLocal
from app.models import User
from app.services.auth_service import AuthService, ROLE_ADMIN
from app.config import settings

def bootstrap_admin(username: str, email: str, password: str, force: bool = False):
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing:
            if not force:
                print(f"[!] User with username '{username}' or email '{email}' already exists (ID: {existing.id}).")
                print("    Use --force to reset this user's password to the provided password.")
                return False
            existing.hashed_password = AuthService.hash_password(password)
            existing.role = ROLE_ADMIN
            existing.is_active = True
            db.commit()
            print(f"[✓] Administrator account '{username}' updated successfully.")
            return True
        else:
            admin_user = User(
                username=username,
                email=email,
                hashed_password=AuthService.hash_password(password),
                full_name="ThreatLens System Administrator",
                role=ROLE_ADMIN,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print(f"[✓] Initial administrator account '{username}' ({email}) created successfully.")
            return True
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap ThreatLens AI Administrator")
    parser.add_argument("--username", default=settings.ADMIN_INITIAL_USERNAME, help="Admin username")
    parser.add_argument("--email", default=settings.ADMIN_INITIAL_EMAIL, help="Admin email")
    parser.add_argument("--password", default=settings.ADMIN_INITIAL_PASSWORD, help="Admin password")
    parser.add_argument("--force", action="store_true", help="Force reset existing admin password")
    args = parser.parse_args()

    success = bootstrap_admin(args.username, args.email, args.password, args.force)
    sys.exit(0 if success else 1)
