# Enhanced Flask Application with Complete Authentication & Authorization
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps 
from credit_risk import calculate_credit_risk
from sqlalchemy import func, or_
from collections import Counter
from flask import request, jsonify
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import Response
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
import pandas as pd
import secrets
import re
import os
import json

# Import db from extensions instead of creating it here
from extensions import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_risk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Initialize db with app BEFORE importing shariah models
db.init_app(app)

# Import Shariah models after db initialization to avoid circular imports
ENHANCED_SHARIAH_AVAILABLE = False
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
    ENHANCED_SHARIAH_AVAILABLE = True
    print("✅ Enhanced Shariah modules loaded successfully")
    
except ImportError as e:
    print(f"⚠️ Enhanced Shariah modules not available: {e}")
    ENHANCED_SHARIAH_AVAILABLE = False

# Load the custom FinBERT model and tokenizer globally
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    tokenizer = AutoTokenizer.from_pretrained("KaidoKirito/shariahfin")
    model = AutoModelForSequenceClassification.from_pretrained("KaidoKirito/shariahfin")
    print("✅ FinBERT model loaded successfully")
except Exception as e:
    print(f"⚠️ Could not load FinBERT model: {e}")
    tokenizer = model = None

# ===== USER ROLES AND MODELS =====
class UserRole(Enum):
    ADMIN = "admin"
    SHARIAH_OFFICER = "shariah_officer" 
    CREDIT_OFFICER = "credit_officer"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    
    # Account status and security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Check if user has specific role"""
        if isinstance(role, str):
            role = UserRole(role)
        return self.role == role
    
    def __repr__(self):
        return f'<User {self.staff_id} - {self.role.value}>'

# ===== BASIC MODELS =====
class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    customer_name = db.Column(db.String(100), nullable=False)
    amount_requested = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.String(50), nullable=True)
    remarks = db.Column(db.String(200), nullable=True)

class CreditApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    property_value = db.Column(db.Float, nullable=False)
    monthly_debt = db.Column(db.Float, nullable=False)
    monthly_income = db.Column(db.Float, nullable=False)
    recovery_rate = db.Column(db.Float, nullable=False)
    probability_of_default = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)

class ShariahRiskApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.String(100), nullable=False)
    application_date = db.Column(db.Date, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_category = db.Column(db.String(50), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    purpose_of_financing = db.Column(db.String(200), nullable=False)
    riba = db.Column(db.String(10), nullable=False)
    gharar = db.Column(db.String(10), nullable=False)
    maysir = db.Column(db.String(10), nullable=False)
    business_description = db.Column(db.Text, nullable=False)
    shariah_risk_score = db.Column(db.String(50), nullable=False)

# ===== DECORATORS =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = User.query.get(session['user_id'])
            
            required_roles = []
            for role in roles:
                if isinstance(role, str):
                    required_roles.append(UserRole(role))
                else:
                    required_roles.append(role)
            
            if user.role not in required_roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ===== BASIC ROUTES =====
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    
    staff_id = request.form.get('staff_id', '').strip()
    password = request.form.get('password', '')
    
    if not staff_id or not password:
        flash('Please enter both Staff ID and password.', 'danger')
        return render_template('login.html')
    
    user = User.query.filter_by(staff_id=staff_id).first()
    
    if not user or not user.check_password(password):
        flash('Invalid staff ID or password.', 'danger')
        return render_template('login.html')
    
    if not user.is_active:
        flash('Your account has been deactivated. Please contact administrator.', 'danger')
        return render_template('login.html')
    
    # Update last login
    user.last_login = datetime.utcnow()
    user.failed_login_attempts = 0
    db.session.commit()
    
    session['user_id'] = user.id
    session['staff_id'] = user.staff_id
    session['role'] = user.role.value
    session['full_name'] = user.full_name
    
    flash(f'Welcome back, {user.full_name}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    loans = Loan.query.order_by(Loan.application_date.desc()).limit(10).all()
    return render_template('index.html', loans=loans)

# ===== LOAN MANAGEMENT ROUTES =====
@app.route('/loan/create', methods=['GET', 'POST'])
@login_required
def create_loan():
    """CREATE_LOAN ROUTE - This was missing and causing the BuildError"""
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        amount_requested = request.form.get('amount_requested', '0')
        remarks = request.form.get('remarks', '').strip()

        if not customer_name:
            flash("Customer name is required!", "danger")
            return redirect(url_for('create_loan'))

        try:
            amount = float(amount_requested)
            if amount <= 0:
                flash("Loan amount must be greater than 0!", "danger")
                return redirect(url_for('create_loan'))
                
            # Simple risk logic: if amount > 50000, mark as "High Risk", else "Low Risk"
            risk_score = "High Risk" if amount > 50000 else "Low Risk"
        except ValueError:
            flash("Invalid loan amount entered!", "danger")
            return redirect(url_for('create_loan'))

        new_loan = Loan(
            customer_name=customer_name,
            amount_requested=amount,
            risk_score=risk_score,
            remarks=remarks
        )
        
        try:
            db.session.add(new_loan)
            db.session.commit()
            flash(f"Loan record created successfully for {customer_name}!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating loan: {str(e)}", "danger")
        
        return redirect(url_for('dashboard'))
    
    return render_template('create.html')

# ===== SHARIAH RISK ROUTES =====
@app.route('/shariah-risk-assessment', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_risk_assessment():
    risk_score = None
    if request.method == 'POST':
        action = request.form.get('action')

        application_id = request.form['application_id']
        application_date = request.form['application_date']
        customer_name = request.form['customer_name']
        amount_requested = float(request.form['amount_requested'])
        purpose_of_financing = request.form['purpose_of_financing']
        customer_category = request.form['customer_category']
        riba = request.form['riba']
        gharar = request.form['gharar']
        maysir = request.form['maysir']
        business_description = request.form['business_description']

        # Predict Shariah Risk using model (if available)
        if model and tokenizer:
            try:
                inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
                with torch.no_grad():
                    outputs = model(**inputs)
                predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
                risk_score = model.config.id2label[predicted_class_id]
            except Exception as e:
                print(f"Model prediction error: {e}")
                risk_score = "Halal"  # Default fallback
        else:
            risk_score = "Halal"  # Default if model not available

        if action == 'save':
            new_shariah_risk = ShariahRiskApplication(
                application_id=application_id,
                application_date=datetime.strptime(application_date, '%Y-%m-%d'),
                customer_name=customer_name,
                customer_category=customer_category,
                loan_amount=amount_requested,
                purpose_of_financing=purpose_of_financing,
                riba=riba,
                gharar=gharar,
                maysir=maysir,
                business_description=business_description,
                shariah_risk_score=risk_score
            )
            db.session.add(new_shariah_risk)
            db.session.commit()
            
            flash(f'Shariah Risk Application saved: {risk_score}', 'success')
            return redirect(url_for('shariah_risk_applications'))

    return render_template('shariah.html', risk_score=risk_score)

@app.route('/shariah-applications')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_risk_applications():
    applications = ShariahRiskApplication.query.order_by(ShariahRiskApplication.id.desc()).all()
    return render_template('shariah_applications.html', applications=applications)

@app.route('/shariah-dashboard')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_dashboard():
    total_count = ShariahRiskApplication.query.count()
    halal_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Halal').count()
    haram_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Haram').count()
    doubtful_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Doubtful').count()

    return render_template(
        'dboard.html',
        total_count=total_count,
        halal_count=halal_count,
        haram_count=haram_count,
        doubtful_count=doubtful_count
    )

# ===== CREDIT RISK ROUTES =====
@app.route('/credit-risk', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_risk_page():
    results = None
    risk_level = None
    risk_score = None

    if request.method == 'POST':
        action = request.form.get('action')

        application_id = request.form['application_id']
        loan_amount = float(request.form['loan_amount'])
        property_value = float(request.form['property_value'])
        monthly_debt = float(request.form['monthly_debt'])
        monthly_income = float(request.form['monthly_income'])
        recovery_rate = float(request.form['recovery_rate']) / 100
        probability_of_default = float(request.form['probability_of_default']) / 100

        try:
            results = calculate_credit_risk(
                loan_amount, property_value, monthly_debt,
                monthly_income, recovery_rate, probability_of_default * 100
            )

            ltv = results['Loan-to-Value (LTV %)']
            dti = results['Debt-to-Income (DTI %)']
            pd = probability_of_default * 100

            risk_score = (ltv * 0.4) + (dti * 0.3) + (pd * 0.3)

            if risk_score < 30:
                risk_level = 'Low'
            elif 30 <= risk_score < 60:
                risk_level = 'Medium'
            else:
                risk_level = 'High'
        except Exception as e:
            flash(f'Error calculating risk: {e}', 'danger')
            return render_template('credit_risks.html')

        if action == 'save':
            new_application = CreditApplication(
                application_id=application_id,
                loan_amount=loan_amount,
                property_value=property_value,
                monthly_debt=monthly_debt,
                monthly_income=monthly_income,
                recovery_rate=recovery_rate * 100,
                probability_of_default=probability_of_default * 100,
                risk_score=risk_score,
                risk_level=risk_level
            )
            db.session.add(new_application)
            db.session.commit()
            
            flash('Credit application saved successfully!', 'success')
            return redirect(url_for('credit_applications'))

    return render_template('credit_risks.html', results=results, risk_level=risk_level, risk_score=risk_score)

@app.route('/credit-applications')
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_applications():
    applications = CreditApplication.query.order_by(CreditApplication.id.desc()).all()
    return render_template('credit_applications.html', applications=applications)

@app.route('/credit-dashboard')
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_dashboard():
    total_count = CreditApplication.query.count()
    low_count = CreditApplication.query.filter_by(risk_level='Low').count()
    medium_count = CreditApplication.query.filter_by(risk_level='Medium').count()
    high_count = CreditApplication.query.filter_by(risk_level='High').count()

    return render_template(
        'dboardcr.html',
        total_count=total_count,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count
    )

# ===== CONTEXT PROCESSORS =====
@app.context_processor
def inject_user():
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
    return {
        'current_user': current_user,
        'UserRole': UserRole
    }

# ===== ERROR HANDLERS =====
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

# ===== INITIALIZATION =====
def create_default_users():
    """Create default users if they don't exist"""
    if User.query.count() == 0:
        # Create Admin user
        admin = User(
            staff_id='admin',
            email='admin@smartrisk.com',
            full_name='System Administrator',
            role=UserRole.ADMIN,
            department='IT',
            is_active=True,
            is_verified=True
        )
        admin.set_password('admin123')
        
        # Create Shariah Officer
        shariah = User(
            staff_id='shariah001',
            email='shariah@smartrisk.com',
            full_name='Ahmad bin Abdullah',
            role=UserRole.SHARIAH_OFFICER,
            department='Shariah Compliance',
            is_active=True,
            is_verified=True
        )
        shariah.set_password('shariah123')
        
        # Create Credit Officer
        credit = User(
            staff_id='credit001',
            email='credit@smartrisk.com',
            full_name='Sarah Lee',
            role=UserRole.CREDIT_OFFICER,
            department='Risk Management',
            is_active=True,
            is_verified=True
        )
        credit.set_password('credit123')
        
        db.session.add_all([admin, shariah, credit])
        db.session.commit()
        print("✅ Default users created successfully!")
        print("👤 Login credentials:")
        print("   Admin: admin / admin123")
        print("   Shariah Officer: shariah001 / shariah123") 
        print("   Credit Officer: credit001 / credit123")

# ===== APPLICATION STARTUP =====
if __name__ == '__main__':
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            
            # Initialize default users
            create_default_users()
            
            print("✅ Database initialized successfully!")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
    
    print("🚀 Starting SMART-Risk Assessment Application...")
    print("📍 Application running on: http://127.0.0.1:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)