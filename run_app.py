#!/usr/bin/env python
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
