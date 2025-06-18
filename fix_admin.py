#!/usr/bin/env python3
"""
Admin Account Recovery Script
Run this script to fix locked admin account and reset password
"""

import sys
import os
from datetime import datetime

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import your Flask app and models
try:
    from app import app, db, User, UserRole
    from werkzeug.security import generate_password_hash
except ImportError as e:
    print(f"Error importing app modules: {e}")
    print("Make sure you're running this script from your project directory")
    sys.exit(1)

def fix_admin_account():
    """Fix the locked admin account"""
    
    with app.app_context():
        try:
            # Find the admin user
            admin_user = User.query.filter_by(staff_id='admin').first()
            
            if not admin_user:
                print("❌ Admin user not found! Creating new admin account...")
                create_new_admin()
                return
            
            print(f"🔍 Found admin user: {admin_user.staff_id}")
            print(f"   Status: {'Active' if admin_user.is_active else 'LOCKED'}")
            print(f"   Failed attempts: {admin_user.failed_login_attempts}")
            
            # Fix the account
            admin_user.is_active = True
            admin_user.failed_login_attempts = 0
            admin_user.updated_at = datetime.utcnow()
            
            # Reset password to a simple one for testing
            new_password = "Admin123!"
            admin_user.set_password(new_password)
            
            # Commit changes
            db.session.commit()
            
            print("✅ Admin account has been fixed!")
            print(f"   Staff ID: admin")
            print(f"   Password: {new_password}")
            print(f"   Status: Active")
            print(f"   Failed attempts: Reset to 0")
            
        except Exception as e:
            print(f"❌ Error fixing admin account: {e}")
            db.session.rollback()

def create_new_admin():
    """Create a new admin account if none exists"""
    
    try:
        # Create new admin user
        new_admin = User(
            staff_id='admin',
            email='admin@smartrisk.com',
            full_name='System Administrator',
            role=UserRole.ADMIN,
            department='IT',
            phone='123-456-7890',
            is_active=True,
            is_verified=True,
            failed_login_attempts=0,
            created_at=datetime.utcnow()
        )
        
        # Set password
        new_password = "Admin123!"
        new_admin.set_password(new_password)
        
        # Add to database
        db.session.add(new_admin)
        db.session.commit()
        
        print("✅ New admin account created!")
        print(f"   Staff ID: admin")
        print(f"   Password: {new_password}")
        print(f"   Email: admin@smartrisk.com")
        print(f"   Role: Admin")
        
    except Exception as e:
        print(f"❌ Error creating admin account: {e}")
        db.session.rollback()

def create_backup_admin():
    """Create a backup admin account"""
    
    with app.app_context():
        try:
            # Check if backup admin already exists
            backup_admin = User.query.filter_by(staff_id='backup_admin').first()
            
            if backup_admin:
                print("🔍 Backup admin already exists, updating...")
                backup_admin.is_active = True
                backup_admin.failed_login_attempts = 0
                backup_admin.set_password("BackupAdmin123!")
            else:
                print("🆕 Creating new backup admin account...")
                backup_admin = User(
                    staff_id='backup_admin',
                    email='backup@smartrisk.com',
                    full_name='Backup Administrator',
                    role=UserRole.ADMIN,
                    department='IT',
                    phone='123-456-7891',
                    is_active=True,
                    is_verified=True,
                    failed_login_attempts=0,
                    created_at=datetime.utcnow()
                )
                backup_admin.set_password("BackupAdmin123!")
                db.session.add(backup_admin)
            
            db.session.commit()
            
            print("✅ Backup admin account ready!")
            print(f"   Staff ID: backup_admin")
            print(f"   Password: BackupAdmin123!")
            
        except Exception as e:
            print(f"❌ Error with backup admin: {e}")
            db.session.rollback()

def list_all_users():
    """List all users in the system"""
    
    with app.app_context():
        try:
            users = User.query.all()
            
            print("\n📋 All users in the system:")
            print("-" * 80)
            print(f"{'Staff ID':<15} {'Name':<25} {'Role':<15} {'Status':<10} {'Failed':<8}")
            print("-" * 80)
            
            for user in users:
                status = "Active" if user.is_active else "LOCKED"
                print(f"{user.staff_id:<15} {user.full_name:<25} {user.role.value:<15} {status:<10} {user.failed_login_attempts:<8}")
            
            print("-" * 80)
            
        except Exception as e:
            print(f"❌ Error listing users: {e}")

if __name__ == "__main__":
    print("🔧 SMART-Risk Admin Account Recovery Tool")
    print("=" * 50)
    
    # Show menu
    print("\nWhat would you like to do?")
    print("1. Fix existing admin account (recommended)")
    print("2. Create backup admin account")
    print("3. List all users")
    print("4. Do all of the above")
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == "1":
        fix_admin_account()
    elif choice == "2":
        create_backup_admin()
    elif choice == "3":
        list_all_users()
    elif choice == "4":
        fix_admin_account()
        create_backup_admin()
        list_all_users()
    else:
        print("Invalid choice. Running option 1 (fix admin account)...")
        fix_admin_account()
    
    print("\n🎉 Done! You should now be able to log in.")
    print("\n💡 Recommended login credentials:")
    print("   Staff ID: admin")
    print("   Password: Admin123!")