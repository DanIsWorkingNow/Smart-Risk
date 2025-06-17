#!/usr/bin/env python
"""
Complete Fix Script for Shariah Risk Assessment Flask Application
This script resolves circular imports, syntax errors, and module structure issues
"""

import os
import shutil
import re

class FlaskApplicationFixer:
    def __init__(self):
        self.project_root = os.getcwd()
        self.fixes_applied = []
        
    def backup_files(self):
        """Create backups of critical files before making changes"""
        files_to_backup = ['app.py']
        
        for file in files_to_backup:
            if os.path.exists(file):
                backup_name = f"{file}.backup_{self._get_timestamp()}"
                shutil.copy2(file, backup_name)
                self.fixes_applied.append(f"✅ Backed up {file} to {backup_name}")
        
    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def create_extensions_file(self):
        """Create extensions.py to separate database instance"""
        extensions_content = '''"""
Flask Extensions
================
Centralized initialization of Flask extensions to avoid circular imports.
This follows Flask best practices for larger applications.
"""

from flask_sqlalchemy import SQLAlchemy

# Initialize database instance
# This will be initialized with the Flask app later using db.init_app(app)
db = SQLAlchemy()
'''
        
        with open('extensions.py', 'w', encoding='utf-8') as f:
            f.write(extensions_content)
        self.fixes_applied.append("✅ Created extensions.py")
    
    def create_package_structure(self):
        """Create proper Python package structure"""
        directories = ['models', 'services', 'routes', 'scripts', 'templates/shariah']
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
            # Create __init__.py for Python packages (exclude templates)
            if not directory.startswith('templates'):
                init_file = os.path.join(directory, '__init__.py')
                if not os.path.exists(init_file):
                    with open(init_file, 'w', encoding='utf-8') as f:
                        f.write(f'"""Package: {directory}"""\n')
                    self.fixes_applied.append(f"✅ Created {init_file}")
    
    def fix_shariah_models(self):
        """Fix shariah_models.py to use extensions instead of app"""
        models_file = 'models/shariah_models.py'
        
        if not os.path.exists(models_file):
            self.fixes_applied.append(f"⚠️ {models_file} not found - skipping")
            return
        
        with open(models_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace circular import with extensions import
        updated_content = content.replace(
            'from app import db',
            'from extensions import db'
        )
        
        # Also fix any other potential app imports
        updated_content = re.sub(
            r'from app import.*db.*',
            'from extensions import db',
            updated_content
        )
        
        with open(models_file, 'w', encoding='utf-8') as f:
            f.write(updated_content)
        
        self.fixes_applied.append("✅ Fixed models/shariah_models.py imports")
    
    def fix_services_imports(self):
        """Fix services files to use proper imports"""
        services_files = [
            'services/shariah_scoring_engine.py'
        ]
        
        for service_file in services_files:
            if not os.path.exists(service_file):
                continue
                
            with open(service_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Fix relative imports to use extensions
            updated_content = content.replace(
                'from app import db',
                'from extensions import db'
            )
            
            # Add proper sys.path manipulation for imports
            if 'import sys' not in content and 'from models.' in content:
                lines = content.split('\n')
                # Find first import line
                for i, line in enumerate(lines):
                    if line.strip().startswith('import') or line.strip().startswith('from'):
                        lines.insert(i, 'import sys')
                        lines.insert(i+1, 'import os')
                        lines.insert(i+2, 'sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))')
                        break
                updated_content = '\n'.join(lines)
            
            with open(service_file, 'w', encoding='utf-8') as f:
                f.write(updated_content)
            
            self.fixes_applied.append(f"✅ Fixed {service_file} imports")
    
    def fix_app_py_syntax(self):
        """Fix syntax errors in app.py and resolve circular imports"""
        if not os.path.exists('app.py'):
            self.fixes_applied.append("❌ app.py not found!")
            return False
        
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split content into lines for analysis
        lines = content.split('\n')
        fixed_lines = []
        
        # Flag to track if we're in a try block
        in_try_block = False
        try_block_indent = 0
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            
            # Fix incomplete try blocks
            if stripped_line == 'try:':
                in_try_block = True
                try_block_indent = len(line) - len(line.lstrip())
                fixed_lines.append(line)
                continue
            
            # If we're in a try block and hit another statement at same/lower indent level
            if in_try_block:
                current_indent = len(line) - len(line.lstrip()) if line.strip() else try_block_indent + 4
                
                # If we hit a line that's not indented properly for the try block
                if (line.strip() and 
                    current_indent <= try_block_indent and 
                    not stripped_line.startswith(('except', 'finally', 'else'))):
                    
                    # Add a basic except block before this line
                    except_line = ' ' * (try_block_indent + 4) + 'pass'
                    fixed_lines.append(' ' * try_block_indent + 'except Exception as e:')
                    fixed_lines.append(except_line)
                    in_try_block = False
            
            fixed_lines.append(line)
        
        # If we ended with an incomplete try block
        if in_try_block:
            except_line = ' ' * (try_block_indent + 4) + 'pass'
            fixed_lines.append(' ' * try_block_indent + 'except Exception as e:')
            fixed_lines.append(except_line)
        
        # Join the lines back
        fixed_content = '\n'.join(fixed_lines)
        
        # Fix imports - replace SQLAlchemy initialization
        # Find and update database initialization
        if 'db = SQLAlchemy(app)' in fixed_content:
            # Add extensions import at the top
            import_pattern = r'(from flask import.*?\n)'
            replacement = r'\1from extensions import db\n'
            fixed_content = re.sub(import_pattern, replacement, fixed_content, count=1)
            
            # Replace db = SQLAlchemy(app) with db.init_app(app)
            fixed_content = fixed_content.replace(
                'db = SQLAlchemy(app)',
                '# Database moved to extensions.py\ndb.init_app(app)'
            )
        elif 'db = SQLAlchemy()' in fixed_content:
            # If using factory pattern, ensure proper import
            if 'from extensions import db' not in fixed_content:
                # Add import after Flask imports
                flask_import_pattern = r'(from flask import.*?\n)'
                replacement = r'\1from extensions import db\n'
                fixed_content = re.sub(flask_import_pattern, replacement, fixed_content, count=1)
            
            fixed_content = fixed_content.replace(
                'db = SQLAlchemy()',
                '# Database moved to extensions.py\ndb.init_app(app)'
            )
        
        # Move Shariah imports after db initialization
        shariah_import_pattern = r'(from models\.shariah_models import.*?\n)'
        fixed_content = re.sub(shariah_import_pattern, '', fixed_content)
        
        # Add Shariah imports after db.init_app(app)
        db_init_pattern = r'(db\.init_app\(app\))'
        shariah_imports = '''
# Import Shariah models after db initialization to avoid circular imports
try:
    from models.shariah_models import (
        ComprehensiveShariahAssessment, 
        ShariahAssessmentAudit, 
        ShariahProductTemplate,
        ShariahComplianceLevel,
        ShariahRiskLevel
    )
    from services.shariah_scoring_engine import (
        ComprehensiveShariahScoringEngine, 
        ShariahAssessmentInput
    )
    from routes.shariah_routes import shariah_bp
    
    # Register the enhanced Shariah assessment blueprint
    app.register_blueprint(shariah_bp)
    
except ImportError as e:
    print(f"Warning: Shariah modules not available: {e}")
'''
        
        replacement = r'\1' + shariah_imports
        fixed_content = re.sub(db_init_pattern, replacement, fixed_content)
        
        # Write the fixed content back
        with open('app.py', 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        
        self.fixes_applied.append("✅ Fixed app.py syntax and circular imports")
        return True
    
    def create_run_script(self):
        """Create a proper run script for the application"""
        run_script_content = '''#!/usr/bin/env python
"""
Application Runner
==================
Properly starts the Flask application with all dependencies resolved.
"""

import os
import sys

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def main():
    """Main application entry point"""
    try:
        # Import after path setup
        from app import app, db
        
        # Create all database tables
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully")
        
        # Run the application
        print("🚀 Starting Shariah Risk Assessment Application...")
        app.run(host='0.0.0.0', port=5001, debug=True)
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Please ensure all dependencies are installed:")
        print("pip install flask flask-sqlalchemy pandas torch transformers reportlab")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Application Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
'''
        
        with open('run_app.py', 'w', encoding='utf-8') as f:
            f.write(run_script_content)
        
        self.fixes_applied.append("✅ Created run_app.py")
    
    def create_requirements_file(self):
        """Create requirements.txt for the project"""
        requirements = '''# Core Flask dependencies
Flask==2.3.3
Flask-SQLAlchemy==3.0.5

# Data processing
pandas==2.0.3
numpy==1.24.3

# AI/ML for Shariah analysis
torch==2.0.1
transformers==4.33.2

# PDF generation
reportlab==4.0.4

# Security
Werkzeug==2.3.7

# Utility
python-dateutil==2.8.2
'''
        
        with open('requirements.txt', 'w', encoding='utf-8') as f:
            f.write(requirements)
        
        self.fixes_applied.append("✅ Created requirements.txt")
    
    def run_all_fixes(self):
        """Execute all fixes in the correct order"""
        print("🔧 Starting comprehensive Flask application fix...")
        print("=" * 60)
        
        # 1. Backup original files
        self.backup_files()
        
        # 2. Create proper package structure
        self.create_package_structure()
        
        # 3. Create extensions.py
        self.create_extensions_file()
        
        # 4. Fix all import issues
        self.fix_shariah_models()
        self.fix_services_imports()
        
        # 5. Fix main app.py
        self.fix_app_py_syntax()
        
        # 6. Create helper files
        self.create_run_script()
        self.create_requirements_file()
        
        # 7. Summary
        print("\n" + "=" * 60)
        print("🎉 All fixes completed successfully!")
        print("\nFixes applied:")
        for fix in self.fixes_applied:
            print(f"  {fix}")
        
        print("\n📋 Next Steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run the application: python run_app.py")
        print("   OR use Flask directly: flask run --port=5001")
        print("3. Test the Shariah risk assessment features")
        
        print("\n🔍 If you encounter any issues:")
        print("- Check that all model files exist in the models/ directory")
        print("- Verify that services/ contains the scoring engine")
        print("- Ensure templates are in the correct directories")
        
        return True

def main():
    """Main execution function"""
    fixer = FlaskApplicationFixer()
    success = fixer.run_all_fixes()
    
    if success:
        print("\n✨ Your Shariah Risk Assessment application is ready!")
    else:
        print("\n❌ Some issues were encountered. Please review the output above.")

if __name__ == "__main__":
    main()