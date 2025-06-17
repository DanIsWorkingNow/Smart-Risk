# SMART-Risk System - Complete Flask Application
# Objectives: 
# PO-1: Shariah risk assessment with machine learning (FinBERT)
# PO-2: File batch upload for credit risk assessment
# PO-3: Complete system testing with all use cases

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from enum import Enum
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

class Loan(db.Model):
    __tablename__ = 'loans'
    
    id = db.Column(db.Integer, primary_key=True)
    application_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    customer_name = db.Column(db.String(100), nullable=False)
    amount_requested = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.String(50), nullable=True)
    remarks = db.Column(db.String(500), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

# ===== SHARIAH RISK ROUTES (PO-1: Machine Learning Implementation) =====
@app.route('/shariah-risk-assessment', methods=['GET', 'POST'])
@role_required(UserRole.SHARIAH_OFFICER, UserRole.ADMIN)
def shariah_risk_assessment():
    risk_score = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # Get form data
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

        # PO-1: AI-Powered Shariah Risk Analysis using FinBERT
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

        if action == 'save':
            new_application = ShariahRiskApplication(
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
                shariah_risk_score=risk_score,
                created_by=session['user_id']
            )
            
            db.session.add(new_application)
            db.session.commit()
            
            AuditLog.log_action(
                user_id=session['user_id'],
                action='SHARIAH_ASSESSMENT_CREATED',
                resource='shariah_application',
                resource_id=application_id,
                details={'risk_score': risk_score},
                request_obj=request
            )
            
            flash(f'Shariah assessment saved: {risk_score}', 'success')
            return redirect(url_for('shariah_risk_applications'))

    return render_template('shariah.html', risk_score=risk_score)

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
@app.route('/credit-risk', methods=['GET', 'POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def credit_risk_page():
    results = None
    risk_level = None
    risk_score = None

    if request.method == 'POST':
        action = request.form.get('action')
        
        # Get form data
        application_id = request.form['application_id']
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

        if action == 'save':
            new_application = CreditApplication(
                application_id=application_id,
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
            db.session.commit()
            
            AuditLog.log_action(
                user_id=session['user_id'],
                action='CREDIT_ASSESSMENT_CREATED',
                resource='credit_application',
                resource_id=application_id,
                details={'risk_level': risk_level, 'risk_score': risk_score},
                request_obj=request
            )
            
            flash('Credit application saved successfully!', 'success')
            return redirect(url_for('credit_applications'))

    return render_template('credit_risks.html', results=results, risk_level=risk_level, risk_score=risk_score)

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
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    applications = CreditApplication.query.order_by(CreditApplication.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('credit_applications.html', applications=applications)

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

# ===== CREDIT APPLICATIONS DELETE ROUTE =====
@app.route('/credit-applications/delete-selected', methods=['POST'])
@role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def delete_selected_credit_applications():
    """Delete selected credit applications"""
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        deleted_count = 0
        for app_id in selected_ids:
            application = CreditApplication.query.get(app_id)
            if application:
                # Log the deletion
                AuditLog.log_action(
                    user_id=session['user_id'],
                    action='CREDIT_APPLICATION_DELETED',
                    resource='credit_application',
                    resource_id=str(application.id),
                    details={'application_id': application.application_id},
                    request_obj=request
                )
                
                db.session.delete(application)
                deleted_count += 1
        
        db.session.commit()
        flash(f'Successfully deleted {deleted_count} application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    
    return redirect(url_for('credit_applications'))

@app.route('/delete-selected-credit-applications', methods=['POST'])
@login_required  # or @role_required(UserRole.CREDIT_OFFICER, UserRole.ADMIN)
def delete_selected_credit_applications():
    """Delete selected credit applications - FIXED ROUTE"""
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        deleted_count = 0
        for app_id in selected_ids:
            application = CreditApplication.query.get(app_id)
            if application:
                # Log the deletion if you have audit logging
                try:
                    AuditLog.log_action(
                        user_id=session['user_id'],
                        action='CREDIT_APPLICATION_DELETED',
                        resource='credit_application',
                        resource_id=str(application.id),
                        details={'application_id': application.application_id},
                        request_obj=request
                    )
                except:
                    pass  # Skip if AuditLog not available
                
                db.session.delete(application)
                deleted_count += 1
        
        db.session.commit()
        flash(f'Successfully deleted {deleted_count} application(s).', 'success')
    else:
        flash('No applications selected.', 'warning')
    
    return redirect(url_for('credit_applications'))  

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
