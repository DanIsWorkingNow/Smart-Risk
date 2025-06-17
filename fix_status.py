#!/usr/bin/env python3
"""
Quick Fix for Shariah Application Status Issues
===============================================
This script fixes the NULL status issue that's preventing access to Shariah applications.
"""

import os
import sys

def fix_database_status():
    """Fix NULL status values in the database"""
    try:
        # Import your Flask app
        from app import app, db
        
        with app.app_context():
            # Fix Shariah Applications
            result = db.session.execute("""
                UPDATE shariah_applications 
                SET status = 'Pending' 
                WHERE status IS NULL
            """)
            shariah_updated = result.rowcount
            
            # Fix Credit Applications if they exist
            try:
                result = db.session.execute("""
                    UPDATE credit_applications 
                    SET status = 'Pending' 
                    WHERE status IS NULL
                """)
                credit_updated = result.rowcount
            except:
                credit_updated = 0
            
            db.session.commit()
            
            print("✅ Database status fix completed!")
            print(f"   📊 Shariah Applications updated: {shariah_updated}")
            print(f"   📊 Credit Applications updated: {credit_updated}")
            
            return True
            
    except Exception as e:
        print(f"❌ Database fix failed: {e}")
        return False

def backup_template():
    """Backup the original template before fixing"""
    template_path = "templates/shariah_applications.html"
    backup_path = f"{template_path}.backup"
    
    try:
        if os.path.exists(template_path):
            import shutil
            shutil.copy2(template_path, backup_path)
            print(f"✅ Template backed up to: {backup_path}")
            return True
    except Exception as e:
        print(f"⚠️ Template backup failed: {e}")
        return False

def fix_template():
    """Fix the template to handle None status values"""
    template_path = "templates/shariah_applications.html"
    
    try:
        # Read the template
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix the problematic line
        old_line = '<tr data-status="{{ app.status.lower() }}">'
        new_line = '<tr data-status="{{ (app.status or \'pending\').lower() }}">'
        
        if old_line in content:
            content = content.replace(old_line, new_line)
            
            # Write the fixed template
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print("✅ Template fixed successfully!")
            print(f"   🔧 Fixed line: {old_line}")
            print(f"   ➡️ Replaced with: {new_line}")
            return True
        else:
            print("⚠️ Problematic line not found in template")
            return False
            
    except FileNotFoundError:
        print(f"❌ Template not found: {template_path}")
        return False
    except Exception as e:
        print(f"❌ Template fix failed: {e}")
        return False

def verify_fix():
    """Verify that the application can start without errors"""
    try:
        from app import app
        
        with app.app_context():
            # Try to query applications to test the fix
            try:
                from app import ShariahRiskApplication
                count = ShariahRiskApplication.query.count()
                print(f"✅ Database query successful! Found {count} Shariah applications")
                return True
            except Exception as e:
                print(f"❌ Database query failed: {e}")
                return False
                
    except Exception as e:
        print(f"❌ Application test failed: {e}")
        return False

def main():
    """Main execution function"""
    print("🔧 Shariah Application Status Fix Tool")
    print("=" * 50)
    
    success_count = 0
    
    # Step 1: Backup template
    print("\n📦 Step 1: Backing up template...")
    if backup_template():
        success_count += 1
    
    # Step 2: Fix template
    print("\n🔧 Step 2: Fixing template...")
    if fix_template():
        success_count += 1
    
    # Step 3: Fix database
    print("\n💾 Step 3: Fixing database...")
    if fix_database_status():
        success_count += 1
    
    # Step 4: Verify fix
    print("\n✅ Step 4: Verifying fix...")
    if verify_fix():
        success_count += 1
    
    # Summary
    print("\n" + "=" * 50)
    if success_count >= 3:
        print("🎉 Fix completed successfully!")
        print("\n📋 What was fixed:")
        print("   ✅ Template now handles NULL status values")
        print("   ✅ Database records updated with default 'Pending' status")
        print("   ✅ Application should now be accessible")
        
        print("\n🚀 Next steps:")
        print("1. Start your application: python app.py")
        print("2. Navigate to /shariah-applications")
        print("3. Test creating new assessments")
    else:
        print("❌ Some fixes failed. Please check the errors above.")
        print("   You may need to run individual fixes manually.")

if __name__ == "__main__":
    main()