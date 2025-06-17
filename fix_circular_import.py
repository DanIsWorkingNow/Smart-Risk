#!/usr/bin/env python
"""
Quick fix script to resolve circular import in Flask app
Run this script to automatically fix the circular import issue
"""

import os
import shutil

def create_extensions_file():
    """Create the extensions.py file"""
    extensions_content = '''# extensions.py
"""
Flask extensions initialization
Separates db instance to avoid circular imports
"""

from flask_sqlalchemy import SQLAlchemy

# Initialize the database instance
db = SQLAlchemy()
'''
    
    with open('extensions.py', 'w') as f:
        f.write(extensions_content)
    print("✅ Created extensions.py")

def update_shariah_models():
    """Update shariah_models.py to use extensions.db"""
    if not os.path.exists('models/shariah_models.py'):
        print("⚠️ models/shariah_models.py not found, skipping update")
        return
    
    # Read the file
    with open('models/shariah_models.py', 'r') as f:
        content = f.read()
    
    # Replace the import
    content = content.replace('from app import db', 'from extensions import db')
    
    # Write back
    with open('models/shariah_models.py', 'w') as f:
        f.write(content)
    
    print("✅ Updated models/shariah_models.py")

def create_init_files():
    """Create __init__.py files in all directories"""
    directories = ['models', 'services', 'routes', 'scripts']
    
    for directory in directories:
        if os.path.exists(directory):
            init_file = os.path.join(directory, '__init__.py')
            if not os.path.exists(init_file):
                with open(init_file, 'w') as f:
                    f.write('# Package initialization\n')
                print(f"✅ Created {init_file}")
            else:
                print(f"ℹ️ {init_file} already exists")

def backup_app_py():
    """Create a backup of app.py"""
    if os.path.exists('app.py'):
        shutil.copy2('app.py', 'app_backup_before_fix.py')
        print("✅ Created backup: app_backup_before_fix.py")

def update_app_py():
    """Update app.py to fix circular import"""
    if not os.path.exists('app.py'):
        print("❌ app.py not found!")
        return False
    
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Check if already fixed
    if 'from extensions import db' in content:
        print("ℹ️ app.py already appears to be fixed")
        return True
    
    # Find the db = SQLAlchemy(app) line and replace it
    if 'db = SQLAlchemy(app)' in content:
        # Add extensions import at the top
        import_section = content.split('\n')
        
        # Find where to insert the extensions import
        insert_line = -1
        for i, line in enumerate(import_section):
            if line.startswith('from flask') or line.startswith('import'):
                insert_line = i + 1
        
        if insert_line > 0:
            import_section.insert(insert_line, 'from extensions import db')
        
        # Remove or comment out the db = SQLAlchemy(app) line
        new_content = []
        for line in import_section:
            if 'db = SQLAlchemy(app)' in line:
                new_content.append('# db = SQLAlchemy(app)  # Moved to extensions.py')
                new_content.append('db.init_app(app)  # Initialize db with app')
            else:
                new_content.append(line)
        
        content = '\n'.join(new_content)
        
        # Write the updated content
        with open('app.py', 'w') as f:
            f.write(content)
        
        print("✅ Updated app.py")
        return True
    else:
        print("⚠️ Could not find 'db = SQLAlchemy(app)' in app.py")
        print("Please manually update app.py as shown in the instructions")
        return False

def main():
    """Main function to run all fixes"""
    print("🔧 Starting circular import fix...")
    print("=" * 50)
    
    # Step 1: Backup current app.py
    backup_app_py()
    
    # Step 2: Create extensions.py
    create_extensions_file()
    
    # Step 3: Create __init__.py files
    create_init_files()
    
    # Step 4: Update shariah_models.py
    update_shariah_models()
    
    # Step 5: Update app.py
    app_updated = update_app_py()
    
    print("\n" + "=" * 50)
    print("🎉 Circular import fix completed!")
    print("\nNext steps:")
    print("1. Review the changes in app.py")
    print("2. Test with: flask run --port=5001")
    print("3. If issues persist, check the manual instructions")
    
    if not app_updated:
        print("\n⚠️ app.py may need manual updates - see instructions above")

if __name__ == "__main__":
    main()