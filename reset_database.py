#!/usr/bin/env python3
"""
Database Reset and Initialization Script
=========================================
This script will:
1. Backup your current database
2. Delete the old database
3. Create a new database with the correct schema
4. Initialize default users and sample data
"""

import os
import shutil
import sys
from datetime import datetime

def backup_existing_database():
    """Backup the current database file"""
    db_files = ['smart_risk.db', 'database.db', 'loans.db']
    
    for db_file in db_files:
        if os.path.exists(db_file):
            backup_name = f"{db_file}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(db_file, backup_name)
            print(f"✅ Backed up {db_file} to {backup_name}")
            
            # Remove the old database
            os.remove(db_file)
            print(f"🗑️ Removed old database: {db_file}")

def reset_database():
    """Reset and recreate the database with correct schema"""
    print("🔄 Resetting database...")
    
    try:
        # Import Flask app
        from app import app, db, User, UserRole
        
        with app.app_context():
            # Drop all existing tables
            db.drop_all()
            print("🗑️ Dropped all existing tables")
            
            # Create all tables with new schema
            db.create_all()
            print("✅ Created all tables with new schema")
            
            # Create default users
            create_default_users(db, User, UserRole)
            
            print("🎉 Database reset completed successfully!")
            
    except Exception as e:
        print(f"❌ Error during database reset: {e}")
        return False
    
    return True

def create_default_users(db, User, UserRole):
    """Create default users for testing"""
    try:
        # Check if users already exist
        if User.query.count() > 0:
            print("ℹ️ Users already exist, skipping creation")
            return
        
        # System Administrator
        admin = User(
            staff_id='admin',
            email='admin@smartrisk.com',
            full_name='System Administrator',
            role=UserRole.ADMIN,
            department='IT Administration',
            is_active=True,
            is_verified=True
        )
        admin.set_password('Admin@123')
        
        # Shariah Risk Officer
        shariah_officer = User(
            staff_id='shariah001',
            email='shariah@smartrisk.com',
            full_name='Ahmad bin Abdullah',
            role=UserRole.SHARIAH_OFFICER,
            department='Shariah Compliance',
            is_active=True,
            is_verified=True
        )
        shariah_officer.set_password('Shariah@123')
        
        # Credit Risk Officer
        credit_officer = User(
            staff_id='credit001',
            email='credit@smartrisk.com',
            full_name='Sarah Lee',
            role=UserRole.CREDIT_OFFICER,
            department='Risk Management',
            is_active=True,
            is_verified=True
        )
        credit_officer.set_password('Credit@123')
        
        # Add all users
        db.session.add_all([admin, shariah_officer, credit_officer])
        db.session.commit()
        
        print("✅ Default users created:")
        print("   Admin: admin / Admin@123")
        print("   Shariah Officer: shariah001 / Shariah@123")
        print("   Credit Officer: credit001 / Credit@123")
        
    except Exception as e:
        print(f"❌ Error creating default users: {e}")
        db.session.rollback()

def verify_database_schema():
    """Verify the database schema is correct"""
    try:
        from app import app, db, CreditApplication, User
        
        with app.app_context():
            # Test if we can access the problematic columns
            count = CreditApplication.query.count()
            user_count = User.query.count()
            
            print(f"✅ Database verification successful!")
            print(f"   Credit Applications: {count}")
            print(f"   Users: {user_count}")
            
            return True
            
    except Exception as e:
        print(f"❌ Database verification failed: {e}")
        return False

def main():
    """Main execution function"""
    print("🔧 SMART-Risk Database Reset Tool")
    print("=" * 50)
    
    # Confirm with user
    response = input("⚠️  This will delete your current database and create a new one. Continue? (y/N): ")
    if response.lower() not in ['y', 'yes']:
        print("❌ Operation cancelled by user")
        return
    
    # Step 1: Backup existing database
    print("\n📦 Step 1: Backing up existing database...")
    backup_existing_database()
    
    # Step 2: Reset database
    print("\n🔄 Step 2: Resetting database...")
    if not reset_database():
        print("❌ Database reset failed!")
        return
    
    # Step 3: Verify schema
    print("\n✅ Step 3: Verifying database schema...")
    if not verify_database_schema():
        print("❌ Database verification failed!")
        return
    
    print("\n" + "=" * 50)
    print("🎉 Database reset completed successfully!")
    print("\n📋 Next steps:")
    print("1. Start your Flask application: python app.py")
    print("2. Login with any of the default users created")
    print("3. Test all the functionality")
    print("\n🔑 Default Login Credentials:")
    print("   Admin: admin / Admin@123")
    print("   Shariah Officer: shariah001 / Shariah@123") 
    print("   Credit Officer: credit001 / Credit@123")

if __name__ == "__main__":
    main()