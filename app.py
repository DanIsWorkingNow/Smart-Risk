# Enhanced Flask Application with Complete Authentication & Authorization
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps 
from transformers import AutoTokenizer, AutoModelForSequenceClassification
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
import torch
import secrets
import re
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_risk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-super-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # 8-hour sessions

db = SQLAlchemy(app)

# Load the custom FinBERT model and tokenizer globally
try:
    tokenizer = AutoTokenizer.from_pretrained("KaidoKirito/shariahfin")
    model = AutoModelForSequenceClassification.from_pretrained("KaidoKirito/shariahfin")
except Exception as e:
    print(f"Warning: Could not load FinBERT model: {e}")
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
    
    def can_access(self, resource):
        """Check if user can access specific resource based on role"""
        permissions = {
            UserRole.ADMIN: [
                'user_management', 'system_settings', 'audit_logs', 
                'data_backup', 'all_assessments', 'system_monitoring'
            ],
            UserRole.SHARIAH_OFFICER: [
                'shariah_assessment', 'shariah_applications', 
                'shariah_reports', 'shariah_dashboard'
            ],
            UserRole.CREDIT_OFFICER: [
                'credit_assessment', 'credit_applications', 
                'credit_reports', 'credit_dashboard', 'file_upload'
            ]
        }
        return resource in permissions.get(self.role, [])
    
    def generate_reset_token(self):
        """Generate password reset token"""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        return self.password_reset_token
    
    def verify_reset_token(self, token):
        """Verify password reset token"""
        return (self.password_reset_token == token and 
                self.password_reset_expires > datetime.utcnow())
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.is_active = False  # Lock account after 5 failed attempts
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
    
    def __repr__(self):
        return f'<User {self.staff_id} - {self.role.value}>'

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(200), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='sessions')
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.JSON, nullable=True)
    
    user = db.relationship('User', backref='audit_logs')
    
    @staticmethod
    def log_action(user_id, action, resource=None, resource_id=None, details=None, request_obj=None):
        """Log user action"""
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details
        )
        
        if request_obj:
            log_entry.ip_address = request_obj.remote_addr
            log_entry.user_agent = request_obj.headers.get('User-Agent')
        
        db.session.add(log_entry)
        db.session.commit()
        return log_entry

# ===== EXISTING MODELS =====
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

# ===== AUTHENTICATION UTILITIES =====
class AuthManager:
    @staticmethod
    def authenticate_user(staff_id, password, request_obj):
        """Authenticate user with staff_id and password"""
        user = User.query.filter_by(staff_id=staff_id).first()
        
        if not user:
            AuditLog.log_action(
                user_id=None,
                action='LOGIN_FAILED',
                details={'reason': 'User not found', 'staff_id': staff_id},
                request_obj=request_obj
            )
            return None, 'Invalid staff ID or password.'
        
        if not user.is_active:
            AuditLog.log_action(
                user_id=user.id,
                action='LOGIN_FAILED',
                details={'reason': 'Account locked'},
                request_obj=request_obj
            )
            return None, 'Your account has been locked. Please contact the administrator.'
        
        if not user.check_password(password):
            user.increment_failed_login()
            db.session.commit()
            
            AuditLog.log_action(
                user_id=user.id,
                action='LOGIN_FAILED',
                details={'reason': 'Invalid password', 'failed_attempts': user.failed_login_attempts},
                request_obj=request_obj
            )
            
            if user.failed_login_attempts >= 5:
                return None, 'Account locked due to too many failed login attempts.'
            
            return None, f'Invalid password. {5 - user.failed_login_attempts} attempts remaining.'
        
        # Successful login
        user.reset_failed_login()
        db.session.commit()
        
        # Create session
        session_token = AuthManager.create_user_session(user, request_obj)
        
        AuditLog.log_action(
            user_id=user.id,
            action='LOGIN_SUCCESS',
            details={'session_token': session_token[:10] + '...'},
            request_obj=request_obj
        )
        
        return user, None
    
    @staticmethod
    def create_user_session(user, request_obj):
        """Create a new user session"""
        session_token = secrets.token_urlsafe(32)
        
        session['user_id'] = user.id
        session['staff_id'] = user.staff_id
        session['role'] = user.role.value
        session['full_name'] = user.full_name
        session['session_token'] = session_token
        session.permanent = True
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=request_obj.remote_addr,
            user_agent=request_obj.headers.get('User-Agent'),
            expires_at=datetime.utcnow() + timedelta(hours=8)
        )
        db.session.add(user_session)
        db.session.commit()
        
        return session_token
    
    @staticmethod
    def logout_user(user_id=None, session_token=None):
        """Logout user and invalidate session"""
        user_id = user_id or session.get('user_id')
        session_token = session_token or session.get('session_token')
        
        if user_id:
            AuditLog.log_action(
                user_id=user_id,
                action='LOGOUT',
                details={'session_token': session_token[:10] + '...' if session_token else None}
            )
            
            if session_token:
                user_session = UserSession.query.filter_by(
                    user_id=user_id, 
                    session_token=session_token
                ).first()
                if user_session:
                    user_session.is_active = False
                    db.session.commit()
        
        session.clear()

# ===== DECORATORS =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
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

def admin_required(f):
    return role_required(UserRole.ADMIN)(f)

def shariah_officer_required(f):
    return role_required(UserRole.SHARIAH_OFFICER)(f)

def credit_officer_required(f):
    return role_required(UserRole.CREDIT_OFFICER)(f)

# ===== HELPER FUNCTIONS =====
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def validate_password_strength(password):
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

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# ===== CONTEXT PROCESSORS =====
@app.context_processor
def inject_user():
    return {
        'current_user': get_current_user(),
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
    
    user, error = AuthManager.authenticate_user(staff_id, password, request)
    
    if error:
        flash(error, 'danger')
        return render_template('login.html')
    
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
    session_token = session.get('session_token')
    
    AuthManager.logout_user(user_id, session_token)
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ===== DASHBOARD ROUTES =====
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    
    # Redirect to role-specific dashboard
    if user.role == UserRole.ADMIN:
        return redirect(url_for('admin_dashboard'))
    elif user.role == UserRole.SHARIAH_OFFICER:
        return redirect(url_for('shariah_dashboard'))
    elif user.role == UserRole.CREDIT_OFFICER:
        return redirect(url_for('credit_dashboard'))
    
    # Default dashboard
    loans = Loan.query.order_by(Loan.application_date.desc()).limit(10).all()
    return render_template('index.html', loans=loans)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Admin dashboard with system statistics
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
    
    if not validate_email(email):
        errors.append('Please enter a valid email address.')
    
    if not validate_password_strength(password):
        errors.append('Password must be at least 8 characters long and contain uppercase, lowercase, number and special character.')
    
    try:
        user_role = UserRole(role)
    except ValueError:
        errors.append('Invalid role selected.')
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return render_template('admin/create_user.html', UserRole=UserRole)
    
    # Create user
    new_user = User(
        staff_id=staff_id,
        email=email,
        full_name=full_name,
        role=user_role,
        department=department,
        phone=phone,
        created_by=session['user_id'],
        is_active=True,
        is_verified=True
    )
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        AuditLog.log_action(
            user_id=session['user_id'],
            action='USER_CREATED',
            resource='user',
            resource_id=new_user.staff_id,
            details={'new_user_role': role},
            request_obj=request
        )
        
        flash(f'User {staff_id} created successfully.', 'success')
        return redirect(url_for('manage_users'))
        
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while creating the user.', 'danger')
        return render_template('admin/create_user.html', UserRole=UserRole)

@app.route('/admin/toggle-user/<int:user_id>')
@admin_required
def toggle_user_status(user_id):
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

# ===== EXISTING ROUTES (WITH AUTHORIZATION) =====
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
            inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
            with torch.no_grad():
                outputs = model(**inputs)
            predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
            risk_score = model.config.id2label[predicted_class_id]
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
            
            AuditLog.log_action(
                user_id=session['user_id'],
                action='SHARIAH_ASSESSMENT_CREATED',
                resource='shariah_application',
                resource_id=application_id,
                request_obj=request
            )
            
            flash(f'Shariah Risk Application saved: {risk_score}', 'success')
            return redirect(url_for('shariah_risk_applications'))

    return render_template('shariah.html', risk_score=risk_score)

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
            
            AuditLog.log_action(
                user_id=session['user_id'],
                action='CREDIT_ASSESSMENT_CREATED',
                resource='credit_application',
                resource_id=application_id,
                request_obj=request
            )
            
            flash('Credit application saved successfully!', 'success')
            return redirect(url_for('credit_applications'))

    return render_template('credit_risks.html', results=results, risk_level=risk_level, risk_score=risk_score)

# ===== DASHBOARD ROUTES =====
@app.route('/shariah-dashboard')
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_dashboard():
    total_count = ShariahRiskApplication.query.count()
    halal_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Halal').count()
    haram_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Haram').count()
    doubtful_count = ShariahRiskApplication.query.filter_by(shariah_risk_score='Doubtful').count()

    purpose_data = db.session.query(
        ShariahRiskApplication.purpose_of_financing,
        func.count(ShariahRiskApplication.purpose_of_financing).label('count')
    ).group_by(
        ShariahRiskApplication.purpose_of_financing
    ).order_by(
        func.count(ShariahRiskApplication.purpose_of_financing).desc()
    ).limit(5).all()

    top_purposes = [{"purpose": row[0], "count": row[1]} for row in purpose_data]

    return render_template(
        'dboard.html',
        total_count=total_count,
        halal_count=halal_count,
        haram_count=haram_count,
        doubtful_count=doubtful_count,
        top_purposes=top_purposes
    )

@app.route('/credit-dashboard')
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_dashboard():
    total_count = CreditApplication.query.count()
    low_count = CreditApplication.query.filter_by(risk_level='Low').count()
    medium_count = CreditApplication.query.filter_by(risk_level='Medium').count()
    high_count = CreditApplication.query.filter_by(risk_level='High').count()

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

    return render_template(
        'dboardcr.html',
        total_count=total_count,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        top_ranges=top_ranges
    )

# ===== OTHER EXISTING ROUTES (ADD AUTHORIZATION AS NEEDED) =====
@app.route('/credit-applications', methods=['GET'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_applications():
    risk_filter = request.args.get('risk_level')
    if risk_filter:
        applications = CreditApplication.query.filter_by(risk_level=risk_filter).order_by(CreditApplication.id.desc()).all()
    else:
        applications = CreditApplication.query.order_by(CreditApplication.id.desc()).all()
    return render_template('credit_applications.html', applications=applications)

@app.route('/shariah-applications', methods=['GET'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_risk_applications():
    risk_filter = request.args.get('risk_score')
    risk_score_mapping = {
        0: "Halal",
        1: "Haram", 
        2: "Doubtful"
    }

    if risk_filter:
        numeric_filter = {v: k for k, v in risk_score_mapping.items()}.get(risk_filter)
        applications = ShariahRiskApplication.query.filter_by(shariah_risk_score=numeric_filter).order_by(ShariahRiskApplication.id.desc()).all()
    else:
        applications = ShariahRiskApplication.query.order_by(ShariahRiskApplication.id.desc()).all()

    for app in applications:
        if app.shariah_risk_score.isdigit():
            app.shariah_risk_score = risk_score_mapping.get(int(app.shariah_risk_score), "Unknown")

    return render_template('shariah_applications.html', applications=applications)

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
        print("Default users created successfully!")
        # Add these missing routes to your app.py file

# ===== BASIC LOAN MANAGEMENT ROUTES (Missing from your current app.py) =====

@app.route('/loan/create', methods=['GET', 'POST'])
@login_required
def create_loan():
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        amount_requested = request.form['amount_requested']
        remarks = request.form.get('remarks', '')

        # Simple risk logic: if amount > 50000, mark as "High Risk", else "Low Risk"
        try:
            amount = float(amount_requested)
            if amount > 50000:
                risk_score = "High Risk"
            else:
                risk_score = "Low Risk"
        except ValueError:
            flash("Invalid amount entered!", "danger")
            return redirect(url_for('create_loan'))

        new_loan = Loan(
            customer_name=customer_name,
            amount_requested=amount,
            risk_score=risk_score,
            remarks=remarks
        )
        db.session.add(new_loan)
        db.session.commit()
        
        AuditLog.log_action(
            user_id=session['user_id'],
            action='LOAN_CREATED',
            resource='loan',
            resource_id=str(new_loan.id),
            request_obj=request
        )
        
        flash("Loan record created successfully!", "success")
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
        
        # Recalculate risk score
        if loan.amount_requested > 50000:
            loan.risk_score = "High Risk"
        else:
            loan.risk_score = "Low Risk"
            
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

# ===== TEST MODEL ROUTE (If referenced in templates) =====
@app.route('/test-shariah-model', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def test_shariah_model():
    risk_score = None
    if request.method == 'POST':
        business_description = request.form['business_description']
        
        # Use the FinBERT model if available
        if model and tokenizer:
            inputs = tokenizer(business_description, return_tensors="pt", truncation=True, padding=True)
            with torch.no_grad():
                outputs = model(**inputs)
            predicted_class_id = torch.argmax(outputs.logits, dim=-1).item()
            risk_score = model.config.id2label[predicted_class_id]
        else:
            # Fallback logic if model not available
            risk_score = "Halal"  # Default for testing
        
        flash(f'Model prediction: {risk_score}', 'success')
    
    return render_template('testmodel.html', risk_score=risk_score)

# ===== CREDIT APPLICATIONS ROUTE FIX =====
@app.route('/credit-applications/delete-selected', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def delete_selected_credit_applications():
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        for app_id in selected_ids:
            application = CreditApplication.query.get(app_id)
            if application:
                db.session.delete(application)
        db.session.commit()
        flash(f'Successfully deleted {len(selected_ids)} application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    return redirect(url_for('credit_applications'))

@app.route('/shariah-applications/delete-selected', methods=['POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def delete_selected_shariah_applications():
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        for app_id in selected_ids:
            application = ShariahRiskApplication.query.get(app_id)
            if application:
                db.session.delete(application)
        db.session.commit()
        flash(f'Successfully deleted {len(selected_ids)} Shariah application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    return redirect(url_for('shariah_risk_applications'))

# ===== FILE UPLOAD HELPER ROUTES =====
@app.route('/upload-credit-file', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def upload_credit_file():
    file = request.files['file']
    if file:
        try:
            if file.filename.endswith('.csv'):
                df = pd.read_csv(file)
            elif file.filename.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file)
            else:
                return jsonify({'error': 'Unsupported file format'}), 400

            if df.empty:
                return jsonify({'error': 'File is empty'}), 400

            # Return first row as sample data
            first_row = df.iloc[0].to_dict()
            return jsonify(first_row)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'No file uploaded'}), 400

@app.route('/generate-pdf-report', methods=['POST'])
@login_required
def generate_pdf_report():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from io import BytesIO
        from flask import Response
        
        data = request.get_json()

        if not data.get('applications'):
            return "No applications data found", 400

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)

        # Add content to the PDF
        c.setFont("Helvetica", 12)
        c.drawString(100, 750, "Credit Application Report")

        y_position = 730
        for application in data['applications']:
            c.drawString(100, y_position, f"Application ID: {application.get('application_id', 'N/A')}")
            c.drawString(100, y_position - 15, f"Loan Amount: {application.get('loan_amount', 'N/A')}")
            c.drawString(100, y_position - 30, f"Risk Level: {application.get('risk_level', 'N/A')}")
            y_position -= 60

            if y_position < 100:
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = 750

        c.save()
        pdf_data = buffer.getvalue()
        buffer.close()

        response = Response(pdf_data, content_type='application/pdf')
        response.headers['Content-Disposition'] = 'attachment; filename=credit_application_report.pdf'
        return response
        
    except ImportError:
        flash('PDF generation feature requires reportlab. Install with: pip install reportlab', 'warning')
        return redirect(url_for('credit_applications'))
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'danger')
        return redirect(url_for('credit_applications'))

# ===== BATCH UPLOAD ROUTES =====
@app.route('/upload-batch-credit', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def upload_batch_credit():
    file = request.files.get('file')
    if not file:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('credit_risk_page'))

    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            flash('Unsupported file format.', 'danger')
            return redirect(url_for('credit_risk_page'))

        applications = []
        errors = 0

        for _, row in df.iterrows():
            try:
                # Calculate risk score and level
                monthly_debt = row['monthly_debt']
                monthly_income = row['monthly_income']
                loan_amount = row['loan_amount']
                property_value = row['property_value']
                probability_of_default = row['probability_of_default']

                dti = monthly_debt / monthly_income
                ltv = loan_amount / property_value
                pd_normalized = probability_of_default / 100

                risk_score = (0.4 * dti + 0.3 * ltv + 0.3 * pd_normalized) * 100

                if risk_score < 40:
                    risk_level = 'Low'
                elif risk_score < 70:
                    risk_level = 'Medium'
                else:
                    risk_level = 'High'

                app = CreditApplication(
                    application_id=row['application_id'],
                    loan_amount=loan_amount,
                    property_value=property_value,
                    monthly_debt=monthly_debt,
                    monthly_income=monthly_income,
                    recovery_rate=row['recovery_rate'],
                    probability_of_default=probability_of_default,
                    risk_score=risk_score,
                    risk_level=risk_level
                )
                applications.append(app)
            except Exception:
                errors += 1
                continue

        db.session.bulk_save_objects(applications)
        db.session.commit()

        flash(f'{len(applications)} applications saved successfully. {errors} failed.', 'success')
    except Exception as e:
        flash(f'Error processing file: {str(e)}', 'danger')

    return redirect(url_for('credit_risk_page'))

@app.route('/preview-credit-file', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def preview_credit_file():
    file = request.files['file']
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400

        preview_data = []
        for _, row in df.iterrows():
            # Calculate risk for preview
            monthly_debt = row['monthly_debt']
            monthly_income = row['monthly_income']
            loan_amount = row['loan_amount']
            property_value = row['property_value']
            probability_of_default = row['probability_of_default']

            dti = monthly_debt / monthly_income
            ltv = loan_amount / property_value
            pd_normalized = probability_of_default / 100

            risk_score = (0.4 * dti + 0.3 * ltv + 0.3 * pd_normalized) * 100

            if risk_score < 40:
                risk_level = 'Low'
            elif risk_score < 70:
                risk_level = 'Medium'
            else:
                risk_level = 'High'

            preview_data.append({
                'application_id': row['application_id'],
                'loan_amount': row['loan_amount'],
                'property_value': row['property_value'],
                'monthly_debt': row['monthly_debt'],
                'monthly_income': row['monthly_income'],
                'recovery_rate': row['recovery_rate'],
                'probability_of_default': row['probability_of_default'],
                'risk_score': risk_score,
                'risk_level': risk_level
            })

        return jsonify(preview_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    # Add these routes to your app.py file

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

@app.route('/admin/user-details/<int:user_id>')
@admin_required
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get user's recent activities from audit logs
    recent_activities = AuditLog.query.filter_by(user_id=user.id)\
                                     .order_by(AuditLog.timestamp.desc())\
                                     .limit(10).all()
    
    # Get user's sessions
    recent_sessions = UserSession.query.filter_by(user_id=user.id)\
                                      .order_by(UserSession.created_at.desc())\
                                      .limit(5).all()
    
    # Calculate some statistics
    total_logins = AuditLog.query.filter_by(user_id=user.id, action='LOGIN_SUCCESS').count()
    failed_logins = AuditLog.query.filter_by(user_id=user.id, action='LOGIN_FAILED').count()
    
    stats = {
        'total_logins': total_logins,
        'failed_logins': failed_logins,
        'last_login': user.last_login,
        'account_created': user.created_at,
        'recent_activities': recent_activities,
        'recent_sessions': recent_sessions
    }
    
    return render_template('admin/user_details.html', user=user, stats=stats)

# Helper function to validate password strength (if not already exists)
def validate_password_strength(password):
    """Validate password meets security requirements"""
    if not password:
        return False
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
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_users()
    app.run(debug=True)