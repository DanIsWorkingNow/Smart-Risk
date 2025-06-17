"""
Flask Extensions
================
Centralized initialization of Flask extensions to avoid circular imports.
"""

from flask_sqlalchemy import SQLAlchemy

# Initialize database instance
db = SQLAlchemy()
