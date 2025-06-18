# SMART-Risk System - Complete Flask Application
# Objectives: 
# PO-1: Shariah risk assessment with machine learning (FinBERT)
# PO-2: File batch upload for credit risk assessment
# PO-3: Complete system testing with all use cases

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # 🆕 ADD THIS LINE
from datetime import datetime, timedelta
from functools import wraps 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from enum import Enum
from credit_risk import calculate_credit_risk, get_risk_level, CreditRiskCalculator, validate_financial_inputs
import pandas as pd
import os
import json
import secrets
import re
from sqlalchemy import func, or_

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_risk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# 🆕 ADD THIS LINE - Initialize Flask-Migrate
migrate = Migrate(app, db)

# Load FinBERT model for Shariah risk analysis (PO-1)
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    tokenizer = AutoTokenizer.from_pretrained("KaidoKirito/shariahfin")
    model = AutoModelForSequenceClassification.from_pretrained("KaidoKirito/shariahfin")
    print("✅ FinBERT model loaded successfully for Shariah risk analysis")
except Exception as e:
    print(f"⚠️ Could not load FinBERT model: {e}")
    tokenizer = model = None

# ===== ENUMS AND MODELS =====
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
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        if isinstance(role, str):
            role = UserRole(role)
        return self.role == role

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    @classmethod
    def log_action(cls, user_id, action, resource, resource_id=None, details=None, request_obj=None):
        try:
            log_entry = cls(
                user_id=user_id,
                action=action,
                resource=resource,
                resource_id=str(resource_id) if resource_id else None,
                details=json.dumps(details) if details else None,
                ip_address=request_obj.remote_addr if request_obj else None,
                user_agent=request_obj.headers.get('User-Agent') if request_obj else None
            )
            db.session.add(log_entry)
            db.session.commit()
        except Exception as e:
            print(f"Error logging action: {e}")

# Updated Loan Model - Replace your existing Loan class in app.py

class Loan(db.Model):
    __tablename__ = 'loans'
    
    # Primary Key
    id = db.Column(db.Integer, primary_key=True)
    
    # Application Details
    application_id = db.Column(db.String(50), unique=True, nullable=False)
    application_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    branch_code = db.Column(db.String(10))
    
    # Customer Information
    ic_number = db.Column(db.String(20), nullable=False)
    customer_name = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    customer_type = db.Column(db.String(20), default='individual')
    address = db.Column(db.Text)
    
    # Financing Details
    product_type = db.Column(db.String(50), nullable=False)
    amount_requested = db.Column(db.Numeric(15, 2), nullable=False)
    loan_term_months = db.Column(db.Integer)
    interest_rate = db.Column(db.Numeric(5, 2))
    purpose_of_financing = db.Column(db.String(100))
    currency = db.Column(db.String(5), default='MYR')
    
    # Calculated Fields
    monthly_payment = db.Column(db.Numeric(15, 2))
    total_interest = db.Column(db.Numeric(15, 2))
    total_payment = db.Column(db.Numeric(15, 2))
    
    # Financial Information
    monthly_income = db.Column(db.Numeric(15, 2))
    existing_commitments = db.Column(db.Numeric(15, 2))
    employment_type = db.Column(db.String(50))
    
    # Collateral Information
    collateral_type = db.Column(db.String(50))
    collateral_value = db.Column(db.Numeric(15, 2))
    ltv_ratio = db.Column(db.Numeric(5, 2))
    
    # Additional Information
    business_description = db.Column(db.Text)
    remarks = db.Column(db.Text)
    risk_category = db.Column(db.String(20), default='medium')
    priority = db.Column(db.String(20), default='normal')
    relationship_manager = db.Column(db.String(100))
    
    # Status and Workflow
    status = db.Column(db.String(50), default='pending')
    risk_score = db.Column(db.String(50))
    credit_score = db.Column(db.Integer)
    approval_status = db.Column(db.String(50), default='pending')
    approved_amount = db.Column(db.Numeric(15, 2))
    
    # Audit Fields
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_loans')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='updated_loans')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_loans')
    
    def __init__(self, **kwargs):
        super(Loan, self).__init__(**kwargs)
        if not self.application_id:
            self.application_id = self.generate_application_id()
    
    def generate_application_id(self):
        """Generate unique application ID"""
        from datetime import datetime
        now = datetime.now()
        timestamp = now.strftime('%Y%m%d%H%M')
        # Get next sequence number for the day
        today_count = Loan.query.filter(
            Loan.application_date == now.date()
        ).count()
        sequence = str(today_count + 1).zfill(3)
        return f"LA{timestamp}{sequence}"
    
    @property
    def status_badge_class(self):
        """Return Bootstrap badge class based on status"""
        status_classes = {
            'pending': 'badge-warning',
            'under_review': 'badge-info',
            'approved': 'badge-success',
            'rejected': 'badge-danger',
            'disbursed': 'badge-primary',
            'completed': 'badge-secondary'
        }
        return status_classes.get(self.status, 'badge-light')
    
    @property
    def risk_badge_class(self):
        """Return Bootstrap badge class based on risk category"""
        risk_classes = {
            'low': 'badge-success',
            'medium': 'badge-warning',
            'high': 'badge-danger'
        }
        return risk_classes.get(self.risk_category, 'badge-secondary')
    
    @property
    def days_since_application(self):
        """Calculate days since application"""
        if self.application_date:
            return (datetime.now().date() - self.application_date).days
        return 0
    
    @property
    def debt_to_income_ratio(self):
        """Calculate debt-to-income ratio"""
        if self.monthly_income and self.monthly_income > 0:
            total_commitments = (self.existing_commitments or 0) + (self.monthly_payment or 0)
            return (total_commitments / self.monthly_income) * 100
        return 0
    
    def can_be_approved(self):
        """Check if loan can be approved based on business rules"""
        if self.status not in ['pending', 'under_review']:
            return False
        
        # Check DTI ratio (should be less than 60%)
        if self.debt_to_income_ratio > 60:
            return False
        
        # Check LTV ratio (should be less than 90% for most products)
        if self.ltv_ratio and self.ltv_ratio > 90:
            return False
        
        return True
    
    def update_status(self, new_status, updated_by_user_id, remarks=None):
        """Update loan status with audit trail"""
        self.status = new_status
        self.updated_by = updated_by_user_id
        self.updated_at = datetime.utcnow()
        
        if remarks:
            existing_remarks = self.remarks or ""
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
            self.remarks = f"{existing_remarks}\n[{timestamp}] Status changed to {new_status}: {remarks}".strip()
    
    def approve(self, approved_by_user_id, approved_amount=None, remarks=None):
        """Approve the loan"""
        self.approval_status = 'approved'
        self.status = 'approved'
        self.approved_by = approved_by_user_id
        self.approved_at = datetime.utcnow()
        self.approved_amount = approved_amount or self.amount_requested
        
        if remarks:
            existing_remarks = self.remarks or ""
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
            self.remarks = f"{existing_remarks}\n[{timestamp}] APPROVED: {remarks}".strip()
    
    def reject(self, rejected_by_user_id, reason):
        """Reject the loan"""
        self.approval_status = 'rejected'
        self.status = 'rejected'
        self.updated_by = rejected_by_user_id
        self.updated_at = datetime.utcnow()
        
        existing_remarks = self.remarks or ""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        self.remarks = f"{existing_remarks}\n[{timestamp}] REJECTED: {reason}".strip()
    
    def to_dict(self):
        """Convert loan object to dictionary"""
        return {
            'id': self.id,
            'application_id': self.application_id,
            'application_date': self.application_date.isoformat() if self.application_date else None,
            'customer_name': self.customer_name,
            'ic_number': self.ic_number,
            'amount_requested': float(self.amount_requested) if self.amount_requested else 0,
            'product_type': self.product_type,
            'status': self.status,
            'approval_status': self.approval_status,
            'risk_category': self.risk_category,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<Loan {self.application_id} - {self.customer_name} - RM{self.amount_requested}>'

# Replace these model sections in your app.py

class CreditApplication(db.Model):
    __tablename__ = 'credit_applications'
    
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
    
    # Status fields for approval system with NAMED CONSTRAINTS
    status = db.Column(db.String(20), default='Pending')  
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_credit_created_by'), nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_credit_approved_by'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_credit_applications')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_credit_applications')

class ShariahRiskApplication(db.Model):
    __tablename__ = 'shariah_applications'
    
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
    
    # Status fields for approval system with NAMED CONSTRAINTS
    status = db.Column(db.String(20), default='Pending')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_shariah_created_by'), nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_shariah_approved_by'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_shariah_applications')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_shariah_applications')

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
            if 'user_id' not in session:
                return redirect(url_for('login'))
                
            user = User.query.get(session['user_id'])
            if not user:
                session.clear()
                return redirect(url_for('login'))
            
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

def admin_required(f):
    return role_required(UserRole.ADMIN)(f)

# ===== UTILITY FUNCTIONS =====
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def allowed_file(filename):
    """Check if file extension is allowed for batch upload"""
    ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ===== CONTEXT PROCESSOR =====
@app.context_processor
def inject_user():
    current_user = get_current_user()
    return {
        'current_user': current_user,
        'UserRole': UserRole
    }

# ===== AUTHENTICATION ROUTES =====
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
    
    if not user:
        flash('Invalid staff ID or password.', 'danger')
        return render_template('login.html')
    
    if not user.is_active:
        flash('Your account has been deactivated. Please contact administrator.', 'danger')
        return render_template('login.html')
    
    if not user.check_password(password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.is_active = False
            flash('Account locked due to multiple failed attempts. Contact administrator.', 'danger')
        else:
            flash('Invalid staff ID or password.', 'danger')
        db.session.commit()
        return render_template('login.html')
    
    # Successful login
    user.last_login = datetime.utcnow()
    user.failed_login_attempts = 0
    db.session.commit()
    
    # Set session
    session['user_id'] = user.id
    session['staff_id'] = user.staff_id
    session['role'] = user.role.value
    session['full_name'] = user.full_name
    
    # Log login action
    AuditLog.log_action(user.id, 'LOGIN', 'user', user.id, request_obj=request)
    
    flash(f'Welcome back, {user.full_name}!', 'success')
    
    # Redirect based on role
    if user.role == UserRole.ADMIN:
        return redirect(url_for('admin_dashboard'))
    elif user.role == UserRole.SHARIAH_OFFICER:
        return redirect(url_for('shariah_dashboard'))
    elif user.role == UserRole.CREDIT_OFFICER:
        return redirect(url_for('credit_dashboard'))
    else:
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    AuditLog.log_action(user_id, 'LOGOUT', 'user', user_id, request_obj=request)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ===== MAIN DASHBOARD ROUTES =====
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    
    # Role-based dashboard redirection
    if user.role == UserRole.ADMIN:
        return redirect(url_for('admin_dashboard'))
    elif user.role == UserRole.SHARIAH_OFFICER:
        return redirect(url_for('shariah_dashboard'))
    elif user.role == UserRole.CREDIT_OFFICER:
        return redirect(url_for('credit_dashboard'))
    
    # Default dashboard
    try:
        loans = Loan.query.order_by(Loan.application_date.desc()).limit(10).all()
        return render_template('index.html', loans=loans)
    except Exception as e:
        print(f"Dashboard error: {e}")
        db.create_all()
        loans = []
        return render_template('index.html', loans=loans)

# ===== ADMIN ROUTES =====
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'credit_applications': CreditApplication.query.count(),
        'shariah_applications': ShariahRiskApplication.query.count(),
        'recent_logins': User.query.filter(User.last_login.isnot(None)).order_by(User.last_login.desc()).limit(5).all()
    }
    return render_template('admin/dashboard.html', stats=stats)

@app.route('/admin/users')
@admin_required
def manage_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    search = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '')
    
    query = User.query
    
    if search:
        query = query.filter(
            or_(
                User.staff_id.contains(search),
                User.full_name.contains(search),
                User.email.contains(search)
            )
        )
    
    if role_filter:
        try:
            query = query.filter(User.role == UserRole(role_filter))
        except ValueError:
            pass
    
    users = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/manage_users.html', 
                         users=users, 
                         search=search, 
                         role_filter=role_filter,
                         UserRole=UserRole)

@app.route('/admin/create-user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'GET':
        return render_template('admin/create_user.html', UserRole=UserRole)
    
    # Get form data
    staff_id = request.form.get('staff_id', '').strip()
    email = request.form.get('email', '').strip()
    full_name = request.form.get('full_name', '').strip()
    role = request.form.get('role', '')
    department = request.form.get('department', '').strip()
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')
    
    # Validation
    errors = []
    
    if not all([staff_id, email, full_name, role, password]):
        errors.append('Please fill in all required fields.')
        
    if User.query.filter_by(staff_id=staff_id).first():
        errors.append('Staff ID already exists.')
        
    if User.query.filter_by(email=email).first():
        errors.append('Email already exists.')
    
    if not validate_password_strength(password):
        errors.append('Password does not meet security requirements.')
    
    try:
        user_role = UserRole(role)
    except ValueError:
        errors.append('Invalid role selected.')
        user_role = None
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return render_template('admin/create_user.html', UserRole=UserRole)
    
    # Create new user
    new_user = User(
        staff_id=staff_id,
        email=email,
        full_name=full_name,
        role=user_role,
        department=department,
        phone=phone,
        is_active=True,
        created_by=session['user_id']
    )
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        AuditLog.log_action(
            user_id=session['user_id'],
            action='USER_CREATED',
            resource='user',
            resource_id=str(new_user.id),
            details={'staff_id': staff_id, 'role': role},
            request_obj=request
        )
        
        flash(f'User {full_name} created successfully!', 'success')
        return redirect(url_for('manage_users'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating user: {str(e)}', 'danger')
        return render_template('admin/create_user.html', UserRole=UserRole)

@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deactivating themselves
    if user.id == session['user_id']:
        flash('You cannot deactivate your own account.', 'warning')
        return redirect(url_for('manage_users'))
    
    # Toggle status
    user.is_active = not user.is_active
    user.updated_by = session['user_id']
    user.updated_at = datetime.utcnow()
    
    action = 'USER_ACTIVATED' if user.is_active else 'USER_DEACTIVATED'
    status = 'activated' if user.is_active else 'deactivated'
    
    db.session.commit()
    
    AuditLog.log_action(
        user_id=session['user_id'],
        action=action,
        resource='user',
        resource_id=str(user.id),
        request_obj=request
    )
    
    flash(f'User {user.full_name} has been {status}.', 'success')
    return redirect(url_for('manage_users'))

# ===== LOAN MANAGEMENT ROUTES =====
@app.route('/loan/create', methods=['GET', 'POST'])
@login_required
def create_loan():
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
                
            # Simple risk calculation
            risk_score = "High Risk" if amount > 50000 else "Low Risk"
        except ValueError:
            flash("Invalid loan amount!", "danger")
            return redirect(url_for('create_loan'))

        new_loan = Loan(
            customer_name=customer_name,
            amount_requested=amount,
            risk_score=risk_score,
            remarks=remarks,
            created_by=session['user_id']
        )
        
        try:
            db.session.add(new_loan)
            db.session.commit()
            
            AuditLog.log_action(
                user_id=session['user_id'],
                action='LOAN_CREATED',
                resource='loan',
                resource_id=str(new_loan.id),
                request_obj=request
            )
            
            flash(f"Loan record created successfully for {customer_name}!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating loan: {str(e)}", "danger")
        
        return redirect(url_for('dashboard'))
    
    return render_template('create.html')

@app.route('/loan/edit/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def edit_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    
    if request.method == 'POST':
        loan.customer_name = request.form['customer_name']
        loan.amount_requested = float(request.form['amount_requested'])
        loan.remarks = request.form.get('remarks', '')
        
        # Recalculate risk
        loan.risk_score = "High Risk" if loan.amount_requested > 50000 else "Low Risk"
        
        db.session.commit()
        
        AuditLog.log_action(
            user_id=session['user_id'],
            action='LOAN_UPDATED',
            resource='loan',
            resource_id=str(loan.id),
            request_obj=request
        )
        
        flash("Loan record updated successfully!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('edit.html', loan=loan)

@app.route('/loan/delete/<int:loan_id>', methods=['POST'])
@login_required
def delete_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    
    AuditLog.log_action(
        user_id=session['user_id'],
        action='LOAN_DELETED',
        resource='loan',
        resource_id=str(loan.id),
        request_obj=request
    )
    
    db.session.delete(loan)
    db.session.commit()
    flash("Loan record deleted successfully!", "success")
    return redirect(url_for('dashboard'))



## ===== CORRECTED SHARIAH RISK ROUTE (Matches Your Frontend) =====
@app.route('/shariah-risk-assessment', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_risk_assessment():
    risk_score = None
    
    if request.method == 'POST':
        action = request.form.get('action')  # 'analyze', 'save', 'approve', 'reject'
        
        # Get form data (matching your frontend field names exactly)
        application_id = request.form['application_id']
        application_date = request.form['application_date']
        customer_name = request.form['customer_name']
        loan_amount = float(request.form['loan_amount'])  # Frontend uses 'loan_amount'
        purpose_of_financing = request.form['purpose_of_financing']
        customer_category = request.form['customer_category']
        riba = request.form['riba']
        gharar = request.form['gharar']
        maysir = request.form['maysir']
        business_description = request.form['business_description']

        # PO-1: AI-Powered Shariah Risk Analysis using FinBERT (PRESERVED)
        if model and tokenizer:
            try:
                # Preprocess text for FinBERT
                combined_text = f"{business_description} {purpose_of_financing}"
                
                inputs = tokenizer(combined_text, return_tensors="pt", truncation=True, padding=True, max_length=512)
                
                with torch.no_grad():
                    outputs = model(**inputs)
                    predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
                    predicted_class_id = torch.argmax(predictions, dim=-1).item()
                    confidence = torch.max(predictions).item()
                
                # Map model output to Shariah compliance
                if hasattr(model.config, 'id2label'):
                    risk_score = model.config.id2label[predicted_class_id]
                else:
                    # Fallback mapping based on prediction confidence
                    if confidence > 0.8:
                        risk_score = "Halal" if predicted_class_id == 0 else "Haram"
                    else:
                        risk_score = "Doubtful"
                
                print(f"FinBERT Analysis - Text: {combined_text[:100]}...")
                print(f"FinBERT Analysis - Prediction: {risk_score}, Confidence: {confidence:.3f}")
                
            except Exception as e:
                print(f"FinBERT model error: {e}")
                # Fallback to rule-based analysis
                risk_score = analyze_shariah_compliance_fallback(riba, gharar, maysir, business_description)
        else:
            # Fallback rule-based analysis
            risk_score = analyze_shariah_compliance_fallback(riba, gharar, maysir, business_description)

        # Handle different actions
        if action in ['save', 'approve', 'reject']:
            try:
                # Check if application already exists
                existing_application = ShariahRiskApplication.query.filter_by(application_id=application_id).first()
                
                if existing_application:
                    # Update existing application
                    existing_application.customer_name = customer_name
                    existing_application.loan_amount = loan_amount
                    existing_application.purpose_of_financing = purpose_of_financing
                    existing_application.customer_category = customer_category
                    existing_application.riba = riba
                    existing_application.gharar = gharar
                    existing_application.maysir = maysir
                    existing_application.business_description = business_description
                    existing_application.shariah_risk_score = risk_score
                    
                    # Set status based on action
                    if action == 'approve':
                        existing_application.status = 'Approved'
                        existing_application.approved_by = session['user_id']
                        existing_application.approved_at = datetime.utcnow()
                    elif action == 'reject':
                        existing_application.status = 'Rejected'
                        existing_application.approved_by = session['user_id']
                        existing_application.approved_at = datetime.utcnow()
                    else:  # save
                        existing_application.status = 'Assessed'
                    
                    application = existing_application
                else:
                    # Create new application
                    status = 'Assessed'
                    approved_by = None
                    approved_at = None
                    
                    if action == 'approve':
                        status = 'Approved'
                        approved_by = session['user_id']
                        approved_at = datetime.utcnow()
                    elif action == 'reject':
                        status = 'Rejected'
                        approved_by = session['user_id']
                        approved_at = datetime.utcnow()
                    
                    application = ShariahRiskApplication(
                        application_id=application_id,
                        application_date=datetime.strptime(application_date, '%Y-%m-%d'),
                        customer_name=customer_name,
                        customer_category=customer_category,
                        loan_amount=loan_amount,
                        purpose_of_financing=purpose_of_financing,
                        riba=riba,
                        gharar=gharar,
                        maysir=maysir,
                        business_description=business_description,
                        shariah_risk_score=risk_score,
                        status=status,
                        created_by=session['user_id'],
                        approved_by=approved_by,
                        approved_at=approved_at
                    )
                    
                    db.session.add(application)
                
                db.session.commit()
                
                # Log the action
                action_map = {
                    'save': 'SHARIAH_ASSESSMENT_SAVED',
                    'approve': 'SHARIAH_APPLICATION_APPROVED',
                    'reject': 'SHARIAH_APPLICATION_REJECTED'
                }
                
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action=action_map[action],
                    resource='shariah_application',
                    resource_id=application_id,
                    details={
                        'risk_score': risk_score,
                        'status': application.status,
                        'finbert_used': bool(model and tokenizer)
                    },
                    request_obj=request
                )
                
                # Flash appropriate message
                if action == 'approve':
                    flash(f'✅ Shariah Application {application_id} has been APPROVED successfully!', 'success')
                elif action == 'reject':
                    flash(f'❌ Shariah Application {application_id} has been REJECTED.', 'warning')
                else:
                    flash(f'💾 Shariah assessment saved: {risk_score}', 'success')
                
                # Redirect to applications list if approved/rejected
                if action in ['approve', 'reject']:
                    return redirect(url_for('shariah_risk_applications'))
                    
            except Exception as e:
                db.session.rollback()
                flash(f'Error processing Shariah application: {str(e)}', 'danger')
        
        # For 'analyze' action, just show results without saving to database

    return render_template('shariah.html', risk_score=risk_score)

# Keep your existing fallback function unchanged
def analyze_shariah_compliance_fallback(riba, gharar, maysir, business_description):
    """Fallback rule-based Shariah compliance analysis"""
    prohibited_keywords = ['interest', 'gambling', 'alcohol', 'pork', 'insurance', 'conventional banking']
    
    # Check explicit prohibitions
    if riba.lower() == 'yes' or gharar.lower() == 'yes' or maysir.lower() == 'present':
        return "Haram"
    
    # Check business description for prohibited activities
    business_lower = business_description.lower()
    for keyword in prohibited_keywords:
        if keyword in business_lower:
            return "Haram"
    
    # Check for doubtful activities
    doubtful_keywords = ['uncertain', 'speculation', 'derivative', 'hedge']
    for keyword in doubtful_keywords:
        if keyword in business_lower:
            return "Doubtful"
    
    return "Halal"

# ===== ADD THESE QUICK APPROVAL ROUTES TO YOUR APP.PY =====

@app.route('/shariah-applications/quick-approve/<int:app_id>', methods=['POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def quick_approve_shariah_application(app_id):
    """Quick approve Shariah application from the list"""
    try:
        application = ShariahRiskApplication.query.get_or_404(app_id)
        
        # Check if already approved/rejected
        if application.status in ['Approved', 'Rejected']:
            flash(f'Shariah Application {application.application_id} is already {application.status.lower()}.', 'warning')
            return redirect(url_for('shariah_risk_applications'))
        
        # Update application status
        application.status = 'Approved'
        application.approved_by = session['user_id']
        application.approved_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='SHARIAH_APPLICATION_QUICK_APPROVED',
            resource='shariah_application',
            resource_id=application.application_id,
            details={
                'shariah_risk_score': application.shariah_risk_score,
                'approval_method': 'quick_approve'
            },
            request_obj=request
        )
        
        flash(f'✅ Shariah Application {application.application_id} has been approved successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving Shariah application: {str(e)}', 'danger')
    
    return redirect(url_for('shariah_risk_applications'))


@app.route('/shariah-applications/quick-reject/<int:app_id>', methods=['POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def quick_reject_shariah_application(app_id):
    """Quick reject Shariah application from the list"""
    try:
        application = ShariahRiskApplication.query.get_or_404(app_id)
        
        # Check if already approved/rejected
        if application.status in ['Approved', 'Rejected']:
            flash(f'Shariah Application {application.application_id} is already {application.status.lower()}.', 'warning')
            return redirect(url_for('shariah_risk_applications'))
        
        # Update application status
        application.status = 'Rejected'
        application.approved_by = session['user_id']
        application.approved_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='SHARIAH_APPLICATION_QUICK_REJECTED',
            resource='shariah_application',
            resource_id=application.application_id,
            details={
                'shariah_risk_score': application.shariah_risk_score,
                'rejection_method': 'quick_reject'
            },
            request_obj=request
        )
        
        flash(f'❌ Shariah Application {application.application_id} has been rejected.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting Shariah application: {str(e)}', 'danger')
    
    return redirect(url_for('shariah_risk_applications'))

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

    return render_template('dboard.html',
        total_count=total_count,
        halal_count=halal_count,
        haram_count=haram_count,
        doubtful_count=doubtful_count
    )

# ===== CREDIT RISK ROUTES (PO-2: Batch File Upload Feature) =====
# Add these updates to your existing credit_risk_page route in app.py

@app.route('/credit-risk', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_risk_page():
    results = None
    risk_level = None
    risk_score = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # Get form data
        application_id = request.form.get('application_id')
        loan_amount = float(request.form['loan_amount'])
        property_value = float(request.form['property_value'])
        monthly_debt = float(request.form['monthly_debt'])
        monthly_income = float(request.form['monthly_income'])
        recovery_rate = float(request.form['recovery_rate'])
        probability_of_default = float(request.form['probability_of_default'])

        # Calculate credit risk metrics
        ltv = (loan_amount / property_value) * 100  # Loan-to-Value ratio
        dti = (monthly_debt / monthly_income) * 100  # Debt-to-Income ratio
        
        # Advanced risk scoring algorithm
        risk_score = (ltv * 0.4) + (dti * 0.3) + (probability_of_default * 0.3)
        
        # Risk level classification
        if risk_score < 30:
            risk_level = 'Low'
        elif risk_score < 60:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
            
        results = {
            'Loan-to-Value (LTV %)': round(ltv, 2),
            'Debt-to-Income (DTI %)': round(dti, 2),
            'Risk Score': round(risk_score, 2),
            'Risk Level': risk_level
        }

        # Handle different actions
        if action in ['save', 'approve', 'reject']:
            # Create or update credit application
            existing_app = CreditApplication.query.filter_by(application_id=application_id).first()
            
            if existing_app:
                # Update existing application
                existing_app.loan_amount = loan_amount
                existing_app.property_value = property_value
                existing_app.monthly_debt = monthly_debt
                existing_app.monthly_income = monthly_income
                existing_app.recovery_rate = recovery_rate
                existing_app.probability_of_default = probability_of_default
                existing_app.risk_score = risk_score
                existing_app.risk_level = risk_level
                
                # Update status based on action
                if action == 'approve':
                    existing_app.status = 'Approved'
                    existing_app.approved_by = session['user_id']
                    existing_app.approved_at = datetime.utcnow()
                elif action == 'reject':
                    existing_app.status = 'Rejected'
                    existing_app.approved_by = session['user_id']
                    existing_app.approved_at = datetime.utcnow()
                else:  # save
                    existing_app.status = 'Assessed'
                
                application = existing_app
            else:
                # Create new application
                status = 'Assessed'
                approved_by = None
                approved_at = None
                
                if action == 'approve':
                    status = 'Approved'
                    approved_by = session['user_id']
                    approved_at = datetime.utcnow()
                elif action == 'reject':
                    status = 'Rejected'
                    approved_by = session['user_id']
                    approved_at = datetime.utcnow()
                
                application = CreditApplication(
                    application_id=application_id,
                    loan_amount=loan_amount,
                    property_value=property_value,
                    monthly_debt=monthly_debt,
                    monthly_income=monthly_income,
                    recovery_rate=recovery_rate,
                    probability_of_default=probability_of_default,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    status=status,
                    created_by=session['user_id'],
                    approved_by=approved_by,
                    approved_at=approved_at
                )
                db.session.add(application)
            
            try:
                db.session.commit()
                
                # Log the action
                action_map = {
                    'save': 'CREDIT_ASSESSMENT_SAVED',
                    'approve': 'CREDIT_APPLICATION_APPROVED', 
                    'reject': 'CREDIT_APPLICATION_REJECTED'
                }
                
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action=action_map[action],
                    resource='credit_application',
                    resource_id=application_id,
                    details={
                        'risk_level': risk_level, 
                        'risk_score': risk_score,
                        'status': application.status
                    },
                    request_obj=request
                )
                
                # Flash appropriate message
                if action == 'approve':
                    flash(f'✅ Application {application_id} has been APPROVED successfully!', 'success')
                elif action == 'reject':
                    flash(f'❌ Application {application_id} has been REJECTED.', 'warning')
                else:
                    flash(f'💾 Credit assessment saved successfully!', 'success')
                
                # Redirect to applications list if approved/rejected
                if action in ['approve', 'reject']:
                    return redirect(url_for('credit_applications'))
                    
            except Exception as e:
                db.session.rollback()
                flash(f'Error processing application: {str(e)}', 'danger')

    return render_template('credit_risks.html', results=results, risk_level=risk_level, risk_score=risk_score)


# Update your CreditApplication model to include status field

# Add this exact route to your app.py file

@app.route('/credit-applications/delete-selected', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def delete_selected_credit_applications():
    """Delete selected credit applications"""
    try:
        selected_ids = request.form.getlist('selected_ids')
        if not selected_ids:
            flash('No applications selected for deletion.', 'warning')
            return redirect(url_for('credit_applications'))
        
        # Convert to integers
        app_ids = [int(id) for id in selected_ids]
        
        # Get applications to be deleted for logging
        applications = CreditApplication.query.filter(CreditApplication.id.in_(app_ids)).all()
        
        # Delete applications
        deleted_count = CreditApplication.query.filter(CreditApplication.id.in_(app_ids)).delete(synchronize_session=False)
        
        db.session.commit()
        
        # Log the action
        for app in applications:
            AuditLog.log_action(
                user_id=session['user_id'],
                action='CREDIT_APPLICATION_DELETED',
                resource='credit_application',
                resource_id=app.application_id,
                details={
                    'deletion_method': 'bulk_delete',
                    'risk_level': app.risk_level,
                    'risk_score': app.risk_score,
                    'status': app.status or 'Pending'  # Safe status handling
                },
                request_obj=request
            )
        
        flash(f'✅ Successfully deleted {deleted_count} credit applications.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting applications: {str(e)}', 'danger')
    
    return redirect(url_for('credit_applications'))

# BONUS: Fix for the SQLAlchemy deprecation warnings you're seeing
# Replace any instances of Model.query.get(id) with db.session.get(Model, id)

# Example fixes for the warnings in your log:
def get_current_user():
    """Fixed version to avoid deprecation warning"""
    if 'user_id' in session:
        return db.session.get(User, session['user_id'])  # Instead of User.query.get()
    return None

# Update any other .query.get() calls in your code similarly

# PO-2: Batch File Upload Feature for Credit Risk Assessment
@app.route('/credit-risk/batch-upload', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_batch_upload():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Process the uploaded file
                results = process_credit_batch_file(filepath)
                
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action='BATCH_UPLOAD_PROCESSED',
                    resource='credit_batch',
                    details={'filename': filename, 'records_processed': len(results)},
                    request_obj=request
                )
                
                flash(f'Successfully processed {len(results)} records from {filename}', 'success')
                return render_template('credit_batch_results.html', results=results)
                
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'danger')
                return redirect(request.url)
            finally:
                # Clean up uploaded file
                if os.path.exists(filepath):
                    os.remove(filepath)
        else:
            flash('Invalid file type. Please upload CSV or Excel files only.', 'danger')
    
    return render_template('credit_batch_upload.html')

def process_credit_batch_file(filepath):
    """Process batch file for credit risk assessment (PO-2)"""
    results = []
    
    try:
        # Read file based on extension
        if filepath.endswith('.csv'):
            df = pd.read_csv(filepath)
        else:
            df = pd.read_excel(filepath)
        
        # Validate required columns
        required_columns = ['application_id', 'loan_amount', 'property_value', 
                          'monthly_debt', 'monthly_income', 'recovery_rate', 'probability_of_default']
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Missing required columns: {', '.join(missing_columns)}")
        
        # Process each row
        for index, row in df.iterrows():
            try:
                # Calculate risk metrics
                loan_amount = float(row['loan_amount'])
                property_value = float(row['property_value'])
                monthly_debt = float(row['monthly_debt'])
                monthly_income = float(row['monthly_income'])
                recovery_rate = float(row['recovery_rate'])
                probability_of_default = float(row['probability_of_default'])
                
                ltv = (loan_amount / property_value) * 100
                dti = (monthly_debt / monthly_income) * 100
                risk_score = (ltv * 0.4) + (dti * 0.3) + (probability_of_default * 0.3)
                
                if risk_score < 30:
                    risk_level = 'Low'
                elif risk_score < 60:
                    risk_level = 'Medium'
                else:
                    risk_level = 'High'
                
                # Save to database
                new_application = CreditApplication(
                    application_id=str(row['application_id']),
                    loan_amount=loan_amount,
                    property_value=property_value,
                    monthly_debt=monthly_debt,
                    monthly_income=monthly_income,
                    recovery_rate=recovery_rate,
                    probability_of_default=probability_of_default,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    created_by=session['user_id']
                )
                
                db.session.add(new_application)
                
                results.append({
                    'application_id': row['application_id'],
                    'loan_amount': loan_amount,
                    'ltv': round(ltv, 2),
                    'dti': round(dti, 2),
                    'risk_score': round(risk_score, 2),
                    'risk_level': risk_level,
                    'status': 'Success'
                })
                
            except Exception as e:
                results.append({
                    'application_id': row.get('application_id', f'Row {index + 1}'),
                    'status': 'Error',
                    'error': str(e)
                })
        
        db.session.commit()
        return results
        
    except Exception as e:
        db.session.rollback()
        raise e

@app.route('/credit-applications')
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_applications():
    """View all credit applications - safely handle NULL status"""
    try:
        # Get filter parameters
        risk_filter = request.args.get('risk_level')
        status_filter = request.args.get('status')
        
        # Build query
        query = CreditApplication.query
        
        if risk_filter:
            query = query.filter_by(risk_level=risk_filter)
        
        if status_filter:
            if status_filter == 'pending':
                # Handle NULL status as pending
                query = query.filter(CreditApplication.status.is_(None))
            else:
                query = query.filter_by(status=status_filter)
        
        # Get all applications
        applications = query.order_by(CreditApplication.id.desc()).all()
        
        return render_template('credit_applications.html', applications=applications)
        
    except Exception as e:
        flash(f'Error loading applications: {str(e)}', 'danger')
        return render_template('credit_applications.html', applications=[])

   

    # ===== UPLOAD CREDIT FILE FOR PREVIEW =====
@app.route('/upload-credit-file', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def upload_credit_file():
    """Upload and preview first row of credit file"""
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    
    try:
        import pandas as pd
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400

        if df.empty:
            return jsonify({'error': 'File is empty'}), 400

        # Return first row for form autofill
        first_row = df.iloc[0].to_dict()
        
        # Convert numpy types to Python types for JSON serialization
        for key, value in first_row.items():
            if pd.isna(value):
                first_row[key] = ''
            else:
                first_row[key] = str(value)
        
        return jsonify(first_row)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/credit-dashboard')
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_dashboard():
    total_count = CreditApplication.query.count()
    low_count = CreditApplication.query.filter_by(risk_level='Low').count()
    medium_count = CreditApplication.query.filter_by(risk_level='Medium').count()
    high_count = CreditApplication.query.filter_by(risk_level='High').count()

    # Calculate ranges for visualization
    applications = CreditApplication.query.with_entities(CreditApplication.loan_amount).all()
    ranges = {'<100k': 0, '100k-500k': 0, '500k-1M': 0, '>1M': 0}
    
    for (amount,) in applications:
        if amount < 100000:
            ranges['<100k'] += 1
        elif amount < 500000:
            ranges['100k-500k'] += 1
        elif amount < 1000000:
            ranges['500k-1M'] += 1
        else:
            ranges['>1M'] += 1

    top_ranges = [{'range': k, 'count': v} for k, v in ranges.items() if v > 0]

    return render_template('dboardcr.html',
        total_count=total_count,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        top_ranges=top_ranges
    )

    

# ===== AUDIT AND REPORTING ROUTES =====
@app.route('/admin/audit-logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = db.session.query(AuditLog, User).join(User, AuditLog.user_id == User.id)
    
    if user_filter:
        query = query.filter(User.staff_id.contains(user_filter))
    
    if action_filter:
        query = query.filter(AuditLog.action.contains(action_filter))
    
    if date_from:
        query = query.filter(AuditLog.timestamp >= datetime.strptime(date_from, '%Y-%m-%d'))
    
    if date_to:
        query = query.filter(AuditLog.timestamp <= datetime.strptime(date_to, '%Y-%m-%d'))
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/audit_logs.html', 
                         logs=logs,
                         user_filter=user_filter,
                         action_filter=action_filter,
                         date_from=date_from,
                         date_to=date_to)

# ===== API ROUTES FOR AJAX REQUESTS =====
@app.route('/api/user-stats')
@admin_required
def api_user_stats():
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'admins': User.query.filter_by(role=UserRole.ADMIN).count(),
        'shariah_officers': User.query.filter_by(role=UserRole.SHARIAH_OFFICER).count(),
        'credit_officers': User.query.filter_by(role=UserRole.CREDIT_OFFICER).count()
    }
    return jsonify(stats)

@app.route('/api/application-stats')
@login_required
def api_application_stats():
    user = get_current_user()
    
    if user.role == UserRole.CREDIT_OFFICER or user.role == UserRole.ADMIN:
        credit_stats = {
            'total': CreditApplication.query.count(),
            'low_risk': CreditApplication.query.filter_by(risk_level='Low').count(),
            'medium_risk': CreditApplication.query.filter_by(risk_level='Medium').count(),
            'high_risk': CreditApplication.query.filter_by(risk_level='High').count()
        }
    else:
        credit_stats = None
    
    if user.role == UserRole.SHARIAH_OFFICER or user.role == UserRole.ADMIN:
        shariah_stats = {
            'total': ShariahRiskApplication.query.count(),
            'halal': ShariahRiskApplication.query.filter_by(shariah_risk_score='Halal').count(),
            'haram': ShariahRiskApplication.query.filter_by(shariah_risk_score='Haram').count(),
            'doubtful': ShariahRiskApplication.query.filter_by(shariah_risk_score='Doubtful').count()
        }
    else:
        shariah_stats = None
    
    return jsonify({
        'credit': credit_stats,
        'shariah': shariah_stats
    })

# ===== ERROR HANDLERS =====
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

# ===== INITIALIZATION FUNCTIONS =====
def create_default_users():
    """Create default users for all three roles"""
    try:
        if User.query.count() == 0:
            # System Administrator (F-2, F-3, F-4: User Management)
            admin = User(
                staff_id='admin',
                email='admin@smartrisk.com',
                full_name='System Administrator',
                role=UserRole.ADMIN,
                department='IT Administration',
                is_active=True
            )
            admin.set_password('Admin@123')
            
            # Shariah Risk Officer (F-6: Shariah Risk Analysis)
            shariah = User(
                staff_id='shariah001',
                email='shariah@smartrisk.com',
                full_name='Ahmad bin Abdullah',
                role=UserRole.SHARIAH_OFFICER,
                department='Shariah Compliance',
                is_active=True
            )
            shariah.set_password('Shariah@123')
            
            # Credit Risk Officer (F-5, F-7: Credit Risk & Batch Upload)
            credit = User(
                staff_id='credit001',
                email='credit@smartrisk.com',
                full_name='Sarah Lee',
                role=UserRole.CREDIT_OFFICER,
                department='Risk Management',
                is_active=True
            )
            credit.set_password('Credit@123')
            
            db.session.add_all([admin, shariah, credit])
            db.session.commit()
            
            print("✅ Default users created successfully!")
            print("🔐 Login Credentials:")
            print("   👑 System Admin: admin / Admin@123")
            print("   🕌 Shariah Officer: shariah001 / Shariah@123")
            print("   💳 Credit Officer: credit001 / Credit@123")
            print("   📝 Note: Please change default passwords after first login")
            
    except Exception as e:
        print(f"❌ Error creating default users: {e}")

def create_sample_data():
    """Create sample data for testing (PO-3: Testing Use Cases)"""
    try:
        # Sample credit applications
        if CreditApplication.query.count() == 0:
            sample_credit = [
                {
                    'application_id': 'CR001',
                    'loan_amount': 250000,
                    'property_value': 400000,
                    'monthly_debt': 2000,
                    'monthly_income': 8000,
                    'recovery_rate': 80,
                    'probability_of_default': 5
                },
                {
                    'application_id': 'CR002',
                    'loan_amount': 500000,
                    'property_value': 600000,
                    'monthly_debt': 4000,
                    'monthly_income': 10000,
                    'recovery_rate': 70,
                    'probability_of_default': 15
                }
            ]
            
            for data in sample_credit:
                ltv = (data['loan_amount'] / data['property_value']) * 100
                dti = (data['monthly_debt'] / data['monthly_income']) * 100
                risk_score = (ltv * 0.4) + (dti * 0.3) + (data['probability_of_default'] * 0.3)
                risk_level = 'Low' if risk_score < 30 else 'Medium' if risk_score < 60 else 'High'
                
                app = CreditApplication(
                    application_id=data['application_id'],
                    loan_amount=data['loan_amount'],
                    property_value=data['property_value'],
                    monthly_debt=data['monthly_debt'],
                    monthly_income=data['monthly_income'],
                    recovery_rate=data['recovery_rate'],
                    probability_of_default=data['probability_of_default'],
                    risk_score=risk_score,
                    risk_level=risk_level,
                    created_by=3  # Credit Officer ID
                )
                db.session.add(app)
        
        # Sample Shariah applications
        if ShariahRiskApplication.query.count() == 0:
            sample_shariah = [
                {
                    'application_id': 'SH001',
                    'customer_name': 'ABC Trading Sdn Bhd',
                    'customer_category': 'Corporate',
                    'loan_amount': 300000,
                    'purpose_of_financing': 'Working capital for halal food distribution',
                    'riba': 'No',
                    'gharar': 'No',
                    'maysir': 'Absent',
                    'business_description': 'Halal food distribution company focusing on certified halal products for local market',
                    'shariah_risk_score': 'Halal'
                },
                {
                    'application_id': 'SH002',
                    'customer_name': 'XYZ Manufacturing',
                    'customer_category': 'Corporate',
                    'loan_amount': 150000,
                    'purpose_of_financing': 'Equipment purchase',
                    'riba': 'No',
                    'gharar': 'Yes',
                    'maysir': 'Absent',
                    'business_description': 'Manufacturing company with uncertain contract terms',
                    'shariah_risk_score': 'Doubtful'
                }
            ]
            
            for data in sample_shariah:
                app = ShariahRiskApplication(
                    application_id=data['application_id'],
                    application_date=datetime.utcnow().date(),
                    customer_name=data['customer_name'],
                    customer_category=data['customer_category'],
                    loan_amount=data['loan_amount'],
                    purpose_of_financing=data['purpose_of_financing'],
                    riba=data['riba'],
                    gharar=data['gharar'],
                    maysir=data['maysir'],
                    business_description=data['business_description'],
                    shariah_risk_score=data['shariah_risk_score'],
                    created_by=2  # Shariah Officer ID
                )
                db.session.add(app)
        
        db.session.commit()
        print("✅ Sample data created for testing")
        
    except Exception as e:
        print(f"❌ Error creating sample data: {e}")


    # Add this route to your app.py file to fix the missing endpoint
@app.route('/upload-batch-credit', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def upload_batch_credit():
    """
    Legacy route for batch upload - redirects to new endpoint
    This maintains compatibility with existing templates
    """
    # Redirect to the new credit_batch_upload route
    return credit_batch_upload()

    # Add these routes to your app.py file
# They are missing and causing the BuildError




# ===== SHARIAH APPLICATIONS DELETE ROUTE =====
@app.route('/shariah-applications/delete-selected', methods=['POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def delete_selected_shariah_applications():
    """Delete selected shariah applications"""
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        deleted_count = 0
        for app_id in selected_ids:
            application = ShariahRiskApplication.query.get(app_id)
            if application:
                # Log the deletion
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action='SHARIAH_APPLICATION_DELETED',
                    resource='shariah_application',
                    resource_id=str(application.id),
                    details={'application_id': application.application_id},
                    request_obj=request
                )
                
                db.session.delete(application)
                deleted_count += 1
        
        db.session.commit()
        flash(f'Successfully deleted {deleted_count} Shariah application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    
    return redirect(url_for('shariah_risk_applications'))

# Add these routes to your current app.py file

@app.route('/admin/change-password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def change_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if not new_password or not confirm_password:
            errors.append('Please enter both password fields.')
        
        if new_password != confirm_password:
            errors.append('Passwords do not match.')
        
        if not validate_password_strength(new_password):
            errors.append('Password does not meet security requirements.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('admin/change_password.html', user=user)
        
        # Change the password
        try:
            user.set_password(new_password)
            user.updated_at = datetime.utcnow()
            user.updated_by = session['user_id']
            
            # Reset failed login attempts when admin changes password
            user.failed_login_attempts = 0
            
            db.session.commit()
            
            # Log the password change
            AuditLog.log_action(
                user_id=session['user_id'],
                action='PASSWORD_CHANGED_BY_ADMIN',
                resource='user',
                resource_id=user.staff_id,
                details={
                    'target_user': user.staff_id,
                    'changed_by_admin': session['staff_id']
                },
                request_obj=request
            )
            
            flash(f'Password successfully changed for user {user.staff_id} ({user.full_name}).', 'success')
            return redirect(url_for('manage_users'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while changing the password. Please try again.', 'danger')
            return render_template('admin/change_password.html', user=user)
    
    return render_template('admin/change_password.html', user=user)

@app.route('/admin/reset-failed-logins/<int:user_id>')
@admin_required
def reset_failed_logins(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.failed_login_attempts > 0:
        old_attempts = user.failed_login_attempts
        user.failed_login_attempts = 0
        user.is_active = True  # Reactivate if locked due to failed attempts
        user.updated_at = datetime.utcnow()
        user.updated_by = session['user_id']
        
        db.session.commit()
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='FAILED_LOGINS_RESET',
            resource='user',
            resource_id=user.staff_id,
            details={
                'target_user': user.staff_id,
                'previous_failed_attempts': old_attempts,
                'reset_by_admin': session['staff_id']
            },
            request_obj=request
        )
        
        flash(f'Failed login attempts reset for user {user.staff_id}. Account has been reactivated.', 'success')
    else:
        flash(f'User {user.staff_id} has no failed login attempts to reset.', 'info')
    
    return redirect(url_for('manage_users'))

# Optional: Fix the existing toggle_user_status route to match template expectations
# You can either update the route URL or keep your current one and update the template
# Here's the route that matches what your template expects:

@app.route('/admin/toggle-user/<int:user_id>')
@admin_required  
def toggle_user_status_get(user_id):
    """GET version for template compatibility"""
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    user.updated_at = datetime.utcnow()
    user.updated_by = session['user_id']
    
    db.session.commit()
    
    action = 'USER_ACTIVATED' if user.is_active else 'USER_DEACTIVATED'
    AuditLog.log_action(
        user_id=session['user_id'],
        action=action,
        resource='user',
        resource_id=user.staff_id,
        request_obj=request
    )
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.staff_id} has been {status}.', 'success')
    return redirect(url_for('manage_users'))


   # ===== ADD THESE COMPLETE APPROVAL ROUTES TO YOUR APP.PY =====

@app.route('/credit-applications/quick-approve/<int:app_id>', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def quick_approve_application(app_id):
    """Quick approve credit application - safe status handling"""
    try:
        application = CreditApplication.query.get_or_404(app_id)
        
        # Check if already approved/rejected (treat NULL as pending)
        if application.status in ['Approved', 'Rejected']:
            flash(f'Application {application.application_id} is already {application.status.lower()}.', 'warning')
            return redirect(url_for('credit_applications'))
        
        # Update application status (safe update)
        application.status = 'Approved'
        application.approved_by = session['user_id']
        application.approved_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='CREDIT_APPLICATION_QUICK_APPROVED',
            resource='credit_application',
            resource_id=application.application_id,
            details={
                'risk_level': application.risk_level,
                'risk_score': application.risk_score,
                'approval_method': 'quick_approve'
            },
            request_obj=request
        )
        
        flash(f'✅ Application {application.application_id} has been approved successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving application: {str(e)}', 'danger')
    
    return redirect(url_for('credit_applications'))


@app.route('/credit-applications/quick-reject/<int:app_id>', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def quick_reject_application(app_id):
    """Quick reject credit application - safe status handling"""
    try:
        application = CreditApplication.query.get_or_404(app_id)
        
        # Check if already approved/rejected (treat NULL as pending)
        if application.status in ['Approved', 'Rejected']:
            flash(f'Application {application.application_id} is already {application.status.lower()}.', 'warning')
            return redirect(url_for('credit_applications'))
        
        # Update application status (safe update)
        application.status = 'Rejected'
        application.approved_by = session['user_id']
        application.approved_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='CREDIT_APPLICATION_QUICK_REJECTED',
            resource='credit_application',
            resource_id=application.application_id,
            details={
                'risk_level': application.risk_level,
                'risk_score': application.risk_score,
                'rejection_method': 'quick_reject'
            },
            request_obj=request
        )
        
        flash(f'❌ Application {application.application_id} has been rejected.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting application: {str(e)}', 'danger')
    
    return redirect(url_for('credit_applications'))

   

# Optional: Add a route to handle pre-filling form from existing application
# ===== ENHANCED CREDIT RISK ASSESSMENT ROUTE =====

@app.route('/credit-risk-assessment', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_risk_assessment():
    """Enhanced credit risk assessment with approval support"""
    if request.method == 'POST':
        action = request.form.get('action')  # 'calculate', 'save', 'approve', 'reject'
        
        # Get form data
        application_id = request.form.get('application_id')
        loan_amount = float(request.form.get('loan_amount', 0))
        property_value = float(request.form.get('property_value', 0))
        monthly_income = float(request.form.get('monthly_income', 0))
        monthly_debt = float(request.form.get('monthly_debt', 0))
        recovery_rate = float(request.form.get('recovery_rate', 0))
        probability_of_default = float(request.form.get('probability_of_default', 0))
        
        # Calculate risk metrics
        ltv = (loan_amount / property_value * 100) if property_value > 0 else 0
        dti = (monthly_debt / monthly_income * 100) if monthly_income > 0 else 0
        
        # Calculate risk score
        risk_score = calculate_credit_risk(ltv, dti, recovery_rate, probability_of_default)
        
        # Determine risk level
        if risk_score <= 30:
            risk_level = 'Low'
        elif risk_score <= 70:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
        
        # Handle different actions
        if action in ['save', 'approve', 'reject']:
            try:
                # Check if application already exists
                existing_app = CreditApplication.query.filter_by(application_id=application_id).first()
                
                if existing_app:
                    # Update existing - safe approach
                    existing_app.loan_amount = loan_amount
                    existing_app.property_value = property_value
                    existing_app.monthly_income = monthly_income
                    existing_app.monthly_debt = monthly_debt
                    existing_app.recovery_rate = recovery_rate
                    existing_app.probability_of_default = probability_of_default
                    existing_app.ltv = ltv
                    existing_app.dti = dti
                    existing_app.risk_score = risk_score
                    existing_app.risk_level = risk_level
                    
                    # Update status only when changing it (preserve existing NULL if just saving)
                    if action == 'approve':
                        existing_app.status = 'Approved'
                        existing_app.approved_by = session['user_id']
                        existing_app.approved_at = datetime.utcnow()
                    elif action == 'reject':
                        existing_app.status = 'Rejected'
                        existing_app.approved_by = session['user_id']
                        existing_app.approved_at = datetime.utcnow()
                    elif action == 'save' and existing_app.status is None:
                        # Only set to 'Assessed' if it was NULL, otherwise keep existing status
                        existing_app.status = 'Assessed'
                    
                    application = existing_app
                else:
                    # Create new application
                    status = 'Assessed'  # Default for new applications
                    approved_by = None
                    approved_at = None
                    
                    if action == 'approve':
                        status = 'Approved'
                        approved_by = session['user_id']
                        approved_at = datetime.utcnow()
                    elif action == 'reject':
                        status = 'Rejected'
                        approved_by = session['user_id']
                        approved_at = datetime.utcnow()
                    
                    application = CreditApplication(
                        application_id=application_id,
                        loan_amount=loan_amount,
                        property_value=property_value,
                        monthly_income=monthly_income,
                        monthly_debt=monthly_debt,
                        recovery_rate=recovery_rate,
                        probability_of_default=probability_of_default,
                        ltv=ltv,
                        dti=dti,
                        risk_score=risk_score,
                        risk_level=risk_level,
                        status=status,
                        created_by=session['user_id'],
                        approved_by=approved_by,
                        approved_at=approved_at
                    )
                    
                    db.session.add(application)
                
                db.session.commit()
                
                # Log action
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action=f'CREDIT_APPLICATION_{action.upper()}',
                    resource='credit_application',
                    resource_id=application_id,
                    details={
                        'risk_score': risk_score,
                        'risk_level': risk_level,
                        'status': application.status or 'Pending'  # Safe status logging
                    },
                    request_obj=request
                )
                
                # Flash message and redirect if approved/rejected
                if action == 'approve':
                    flash(f'✅ Credit Application {application_id} has been APPROVED!', 'success')
                    return redirect(url_for('credit_applications'))
                elif action == 'reject':
                    flash(f'❌ Credit Application {application_id} has been REJECTED!', 'warning')
                    return redirect(url_for('credit_applications'))
                else:
                    flash(f'💾 Credit assessment saved successfully!', 'success')
                    
            except Exception as e:
                db.session.rollback()
                flash(f'Error processing application: {str(e)}', 'danger')
        
        # Return results for display
        return render_template('credit_risk.html', 
                             ltv=ltv, 
                             dti=dti, 
                             risk_score=risk_score, 
                             risk_level=risk_level)
    
    return render_template('credit_risk.html')


# Database Migration Commands
"""
After updating your CreditApplication model, run these commands:

1. Create migration:
   flask db migrate -m "Add approval status fields to CreditApplication"

2. Apply migration:
   flask db upgrade

3. If you need to add the fields manually, here's the SQL:
   ALTER TABLE credit_application ADD COLUMN status VARCHAR(20) DEFAULT 'Pending';
   ALTER TABLE credit_application ADD COLUMN approved_by INTEGER;
   ALTER TABLE credit_application ADD COLUMN approved_at DATETIME;
   ALTER TABLE credit_application ADD FOREIGN KEY (approved_by) REFERENCES user(id);
"""


# Add these routes to your app.py

@app.route('/loans')
@login_required
def view_loans():
    """View all loan applications with filtering and statistics"""
    
    # Get filter parameters
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Base query
    query = Loan.query
    
    # Apply role-based filtering
    user = get_current_user()
    if user.role == UserRole.CREDIT_OFFICER:
        # Credit officers see all loans
        pass
    elif user.role == UserRole.SHARIAH_OFFICER:
        # Shariah officers see loans that need Shariah review
        query = query.filter(Loan.product_type.in_(['murabaha', 'musharakah', 'mudarabah', 'ijara', 'tawarruq', 'bba']))
    elif user.role == UserRole.ADMIN:
        # Admins see all loans
        pass
    
    # Apply filters
    if status_filter:
        query = query.filter(Loan.status == status_filter)
    
    if search:
        query = query.filter(
            or_(
                Loan.application_id.contains(search),
                Loan.customer_name.contains(search),
                Loan.ic_number.contains(search)
            )
        )
    
    # Get paginated results
    loans = query.order_by(Loan.application_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Calculate statistics
    stats = {
        'pending': Loan.query.filter_by(status='pending').count(),
        'under_review': Loan.query.filter_by(status='under_review').count(),
        'approved': Loan.query.filter_by(status='approved').count(),
        'rejected': Loan.query.filter_by(status='rejected').count(),
        'total_amount': db.session.query(func.sum(Loan.amount_requested)).scalar() or 0
    }
    
    return render_template('view_loans.html', 
                         loans=loans.items, 
                         pagination=loans,
                         stats=stats,
                         status_filter=status_filter,
                         search=search)

@app.route('/loans/<int:loan_id>')
@login_required
def view_loan_details(loan_id):
    """View detailed information for a specific loan"""
    
    loan = Loan.query.get_or_404(loan_id)
    
    # Check permissions
    user = get_current_user()
    if user.role not in [UserRole.ADMIN, UserRole.CREDIT_OFFICER, UserRole.SHARIAH_OFFICER]:
        flash('You do not have permission to view loan details.', 'danger')
        return redirect(url_for('view_loans'))
    
    return render_template('loan_details.html', loan=loan)

@app.route('/loans/<int:loan_id>/edit', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def edit_loan(loan_id):
    """Edit an existing loan application"""
    
    loan = Loan.query.get_or_404(loan_id)
    
    # Check if loan can be edited
    if loan.status in ['approved', 'rejected', 'disbursed']:
        flash('This loan cannot be edited as it has been processed.', 'warning')
        return redirect(url_for('view_loan_details', loan_id=loan_id))
    
    if request.method == 'POST':
        try:
            # Update loan fields from form
            loan.customer_name = request.form.get('customer_name', loan.customer_name)
            loan.ic_number = request.form.get('ic_number', loan.ic_number)
            loan.phone = request.form.get('phone', loan.phone)
            loan.email = request.form.get('email', loan.email)
            loan.address = request.form.get('address', loan.address)
            loan.customer_type = request.form.get('customer_type', loan.customer_type)
            
            loan.product_type = request.form.get('product_type', loan.product_type)
            loan.amount_requested = float(request.form.get('amount_requested', loan.amount_requested))
            loan.loan_term_months = int(request.form.get('loan_term_months', loan.loan_term_months or 36))
            loan.interest_rate = float(request.form.get('interest_rate', loan.interest_rate or 8.5))
            loan.purpose_of_financing = request.form.get('purpose_of_financing', loan.purpose_of_financing)
            
            loan.monthly_income = float(request.form.get('monthly_income', 0)) or None
            loan.existing_commitments = float(request.form.get('existing_commitments', 0)) or None
            loan.employment_type = request.form.get('employment_type', loan.employment_type)
            
            loan.collateral_type = request.form.get('collateral_type', loan.collateral_type)
            loan.collateral_value = float(request.form.get('collateral_value', 0)) or None
            loan.ltv_ratio = float(request.form.get('ltv_ratio', 0)) or None
            
            loan.business_description = request.form.get('business_description', loan.business_description)
            loan.remarks = request.form.get('remarks', loan.remarks)
            loan.risk_category = request.form.get('risk_category', loan.risk_category)
            loan.priority = request.form.get('priority', loan.priority)
            
            # Recalculate loan payments
            if loan.amount_requested and loan.loan_term_months and loan.interest_rate:
                monthly_rate = loan.interest_rate / 100 / 12
                if monthly_rate > 0:
                    loan.monthly_payment = loan.amount_requested * (monthly_rate * (1 + monthly_rate)**loan.loan_term_months) / ((1 + monthly_rate)**loan.loan_term_months - 1)
                    loan.total_payment = loan.monthly_payment * loan.loan_term_months
                    loan.total_interest = loan.total_payment - loan.amount_requested
            
            # Update audit fields
            loan.updated_by = session['user_id']
            loan.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            flash('Loan application updated successfully!', 'success')
            return redirect(url_for('view_loan_details', loan_id=loan_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating loan: {str(e)}', 'danger')
    
    return render_template('edit_loan.html', loan=loan)

@app.route('/loans/<int:loan_id>/approve', methods=['GET', 'POST'])
@role_required(UserRole.ADMIN, UserRole.CREDIT_OFFICER)
def approve_loan(loan_id):
    """Approve a loan application"""
    
    loan = Loan.query.get_or_404(loan_id)
    
    if loan.status not in ['pending', 'under_review']:
        flash('This loan cannot be approved.', 'warning')
        return redirect(url_for('view_loan_details', loan_id=loan_id))
    
    if request.method == 'POST':
        approved_amount = float(request.form.get('approved_amount', loan.amount_requested))
        remarks = request.form.get('remarks', '')
        
        # Approve the loan
        loan.approve(session['user_id'], approved_amount, remarks)
        
        # Create audit log
        AuditLog.log_action(
            user_id=session['user_id'],
            action='LOAN_APPROVED',
            resource='loan',
            resource_id=loan.application_id,
            details={'approved_amount': approved_amount, 'original_amount': float(loan.amount_requested)},
            request_obj=request
        )
        
        db.session.commit()
        flash(f'Loan {loan.application_id} approved successfully!', 'success')
        return redirect(url_for('view_loans'))
    
    return render_template('approve_loan.html', loan=loan)

@app.route('/loans/<int:loan_id>/reject', methods=['GET', 'POST'])
@role_required(UserRole.ADMIN, UserRole.CREDIT_OFFICER)
def reject_loan(loan_id):
    """Reject a loan application"""
    
    loan = Loan.query.get_or_404(loan_id)
    
    if loan.status not in ['pending', 'under_review']:
        flash('This loan cannot be rejected.', 'warning')
        return redirect(url_for('view_loan_details', loan_id=loan_id))
    
    if request.method == 'POST':
        reason = request.form.get('reason', 'No reason provided')
        
        # Reject the loan
        loan.reject(session['user_id'], reason)
        
        # Create audit log
        AuditLog.log_action(
            user_id=session['user_id'],
            action='LOAN_REJECTED',
            resource='loan',
            resource_id=loan.application_id,
            details={'reason': reason},
            request_obj=request
        )
        
        db.session.commit()
        flash(f'Loan {loan.application_id} rejected.', 'info')
        return redirect(url_for('view_loans'))
    
    return render_template('reject_loan.html', loan=loan)

@app.route('/loans/<int:loan_id>/delete', methods=['POST'])
@admin_required
def delete_loan(loan_id):
    """Delete a loan application (admin only)"""
    
    loan = Loan.query.get_or_404(loan_id)
    
    # Create audit log before deletion
    AuditLog.log_action(
        user_id=session['user_id'],
        action='LOAN_DELETED',
        resource='loan',
        resource_id=loan.application_id,
        details={'customer_name': loan.customer_name, 'amount': float(loan.amount_requested)},
        request_obj=request
    )
    
    db.session.delete(loan)
    db.session.commit()
    
    flash(f'Loan application {loan.application_id} deleted.', 'info')
    return redirect(url_for('view_loans'))

@app.route('/loans/bulk-approve', methods=['POST'])
@role_required(UserRole.ADMIN, UserRole.CREDIT_OFFICER)
def bulk_approve_loans():
    """Bulk approve multiple loans"""
    
    selected_loans = request.form.getlist('selected_loans')
    
    if not selected_loans:
        flash('No loans selected for approval.', 'warning')
        return redirect(url_for('view_loans'))
    
    approved_count = 0
    for loan_id in selected_loans:
        loan = Loan.query.get(loan_id)
        if loan and loan.status in ['pending', 'under_review'] and loan.can_be_approved():
            loan.approve(session['user_id'], remarks='Bulk approval')
            approved_count += 1
    
    db.session.commit()
    flash(f'{approved_count} loans approved successfully!', 'success')
    return redirect(url_for('view_loans'))

@app.route('/loans/bulk-reject', methods=['POST'])
@role_required(UserRole.ADMIN, UserRole.CREDIT_OFFICER)
def bulk_reject_loans():
    """Bulk reject multiple loans"""
    
    selected_loans = request.form.getlist('selected_loans')
    
    if not selected_loans:
        flash('No loans selected for rejection.', 'warning')
        return redirect(url_for('view_loans'))
    
    rejected_count = 0
    for loan_id in selected_loans:
        loan = Loan.query.get(loan_id)
        if loan and loan.status in ['pending', 'under_review']:
            loan.reject(session['user_id'], 'Bulk rejection')
            rejected_count += 1
    
    db.session.commit()
    flash(f'{rejected_count} loans rejected.', 'info')
    return redirect(url_for('view_loans'))

@app.route('/loans/export')
@login_required
def export_loans():
    """Export loans to CSV"""
    
    import csv
    from io import StringIO
    
    # Get loans based on user role
    user = get_current_user()
    query = Loan.query
    
    if user.role == UserRole.SHARIAH_OFFICER:
        query = query.filter(Loan.product_type.in_(['murabaha', 'musharakah', 'mudarabah', 'ijara', 'tawarruq', 'bba']))
    
    loans = query.order_by(Loan.application_date.desc()).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Application ID', 'Application Date', 'Customer Name', 'IC Number',
        'Product Type', 'Amount Requested', 'Term (Months)', 'Interest Rate',
        'Monthly Payment', 'Status', 'Risk Category', 'Priority',
        'Monthly Income', 'DTI Ratio', 'Created Date'
    ])
    
    # Write data
    for loan in loans:
        writer.writerow([
            loan.application_id,
            loan.application_date.strftime('%Y-%m-%d') if loan.application_date else '',
            loan.customer_name,
            loan.ic_number,
            loan.product_type,
            float(loan.amount_requested) if loan.amount_requested else 0,
            loan.loan_term_months or '',
            float(loan.interest_rate) if loan.interest_rate else '',
            float(loan.monthly_payment) if loan.monthly_payment else '',
            loan.status,
            loan.risk_category,
            loan.priority,
            float(loan.monthly_income) if loan.monthly_income else '',
            f"{loan.debt_to_income_ratio:.1f}%" if loan.debt_to_income_ratio > 0 else '',
            loan.created_at.strftime('%Y-%m-%d %H:%M') if loan.created_at else ''
        ])
    
    # Create response
    from flask import make_response
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=loans_export_{datetime.now().strftime("%Y%m%d_%H%M")}.csv'
    
    return response

# Update your create_loan route to handle the new form fields
@app.route('/loan/create', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def create_loan():
    if request.method == 'GET':
        return render_template('create.html')
    
    try:
        # Create new loan with all the comprehensive fields
        new_loan = Loan(
            # Application details
            application_id=request.form.get('application_id'),
            branch_code=request.form.get('branch_code'),
            
            # Customer information
            ic_number=request.form.get('ic_number'),
            customer_name=request.form.get('customer_name'),
            phone=request.form.get('phone'),
            email=request.form.get('email'),
            customer_type=request.form.get('customer_type', 'individual'),
            address=request.form.get('address'),
            
            # Financing details
            product_type=request.form.get('product_type'),
            amount_requested=float(request.form.get('amount_requested')),
            loan_term_months=int(request.form.get('loan_term_months', 36)),
            interest_rate=float(request.form.get('interest_rate', 8.5)),
            purpose_of_financing=request.form.get('purpose_of_financing'),
            currency=request.form.get('currency', 'MYR'),
            
            # Calculated fields
            monthly_payment=float(request.form.get('monthly_payment', 0)) or None,
            total_interest=float(request.form.get('total_interest', 0)) or None,
            total_payment=float(request.form.get('total_payment', 0)) or None,
            
            # Financial information
            monthly_income=float(request.form.get('monthly_income', 0)) or None,
            existing_commitments=float(request.form.get('existing_commitments', 0)) or None,
            employment_type=request.form.get('employment_type'),
            
            # Collateral information
            collateral_type=request.form.get('collateral_type'),
            collateral_value=float(request.form.get('collateral_value', 0)) or None,
            ltv_ratio=float(request.form.get('ltv_ratio', 0)) or None,
            
            # Additional information
            business_description=request.form.get('business_description'),
            remarks=request.form.get('remarks'),
            risk_category=request.form.get('risk_category', 'medium'),
            priority=request.form.get('priority', 'normal'),
            relationship_manager=request.form.get('relationship_manager'),
            
            # Audit fields
            created_by=session['user_id'],
            status='pending',
            approval_status='pending'
        )
        
        db.session.add(new_loan)
        db.session.commit()
        
        # Create audit log
        AuditLog.log_action(
            user_id=session['user_id'],
            action='LOAN_CREATED',
            resource='loan',
            resource_id=new_loan.application_id,
            details={
                'customer_name': new_loan.customer_name,
                'amount': float(new_loan.amount_requested),
                'product_type': new_loan.product_type
            },
            request_obj=request
        )
        
        flash(f'Loan application {new_loan.application_id} created successfully!', 'success')
        return redirect(url_for('view_loans'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating loan application: {str(e)}', 'danger')
        return render_template('create.html')



# ===== GENERATE PDF REPORT ROUTE =====
@app.route('/generate-pdf-report', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def generate_pdf_report():
    """Generate PDF report for selected applications"""
    try:
        # Import reportlab for PDF generation
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        import json
        
        # Get the JSON data from request
        data = request.get_json()
        applications = data.get('applications', [])
        
        if not applications:
            return jsonify({'error': 'No applications provided'}), 400
        
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        title = Paragraph("Credit Risk Assessment Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Table data
        table_data = [
            ['Application ID', 'Loan Amount', 'Property Value', 'Monthly Income', 'Risk Score', 'Risk Level']
        ]
        
        for app in applications:
            table_data.append([
                app.get('application_id', ''),
                f"RM {app.get('loan_amount', '')}",
                f"RM {app.get('property_value', '')}",
                f"RM {app.get('monthly_income', '')}",
                f"{app.get('risk_score', '')}%",
                app.get('risk_level', '')
            ])
        
        # Create table
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        
        # Log the action
        AuditLog.log_action(
            user_id=session['user_id'],
            action='PDF_REPORT_GENERATED',
            resource='credit_report',
            details={'applications_count': len(applications)},
            request_obj=request
        )
        
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': 'attachment; filename=credit_risk_report.pdf',
                'Content-Type': 'application/pdf'
            }
        )
        
    except ImportError:
        return jsonify({'error': 'PDF generation library not installed. Install with: pip install reportlab'}), 500
    except Exception as e:
        return jsonify({'error': f'Error generating PDF: {str(e)}'}), 500


@app.route('/debug-routes')
def debug_routes():
    """Temporary route to debug all available endpoints"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'url': rule.rule,
            'methods': list(rule.methods)
        })
    
    # Return as JSON or HTML for debugging
    return '<br>'.join([f"{r['endpoint']}: {r['url']} {r['methods']}" for r in routes])


# ===== APPLICATION STARTUP =====
if __name__ == '__main__':
    with app.app_context():
        try:
            # Create all database tables
            db.create_all()
            print("✅ Database tables created")
            
            # Create default users (F-2: Register New User functionality)
            create_default_users()
            
            # Create sample data for testing (PO-3: Testing Use Cases)
            create_sample_data()
            
            print("✅ SMART-Risk System initialized successfully!")
            print("🎯 Project Objectives Implementation:")
            print("   PO-1: ✅ Shariah risk assessment with FinBERT ML model")
            print("   PO-2: ✅ Batch file upload for credit risk assessment")
            print("   PO-3: ✅ Complete system with all use cases ready for testing")
            print("📋 Features Implemented:")
            print("   F-1: ✅ User Login")
            print("   F-2: ✅ Register New User (Admin)")
            print("   F-3: ✅ Terminate User Account (Admin)")
            print("   F-4: ✅ Manage Users (Admin)")
            print("   F-5: ✅ Calculate Credit Risk")
            print("   F-6: ✅ Analyse Shariah Risk with ML")
            print("   F-7: ✅ Upload File Batch")
            print("   F-8: ✅ View Past Records")
            print("   F-11: ✅ Save Risk Assessment")
            print("   F-13: ✅ View Audit Trail & Logs")
            
        except Exception as e:
            print(f"❌ Initialization error: {e}")
    
    print("🚀 Starting SMART-Risk System on http://127.0.0.1:5001")
    print("🔗 Access your application at: http://localhost:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)