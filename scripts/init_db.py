# scripts/init_db.py
"""
Simplified Database Initialization Script for SMART-Risk system
This script creates all necessary tables and populates them with default data
"""

import os
import sys
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

# Add the parent directory to path to import from app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Flask app and models
from app import app, db, User, UserRole, Loan, CreditApplication, ShariahRiskApplication, AuditLog

def create_default_users():
    """Create default users for the system"""
    print("Creating default users...")
    
    users_data = [
        {
            'staff_id': 'admin',
            'email': 'admin@smartrisk.com',
            'full_name': 'System Administrator',
            'role': UserRole.ADMIN,
            'department': 'Information Technology',
            'phone': '+60123456789',
            'password': 'admin123'
        },
        {
            'staff_id': 'shariah001',
            'email': 'shariah@smartrisk.com',
            'full_name': 'Ahmad bin Abdullah',
            'role': UserRole.SHARIAH_OFFICER,
            'department': 'Shariah Compliance',
            'phone': '+60123456788',
            'password': 'shariah123'
        },
        {
            'staff_id': 'credit001',
            'email': 'credit@smartrisk.com',
            'full_name': 'Sarah Lee',
            'role': UserRole.CREDIT_OFFICER,
            'department': 'Risk Management',
            'phone': '+60123456787',
            'password': 'credit123'
        },
        {
            'staff_id': 'shariah002',
            'email': 'shariah2@smartrisk.com',
            'full_name': 'Fatimah binti Hassan',
            'role': UserRole.SHARIAH_OFFICER,
            'department': 'Shariah Compliance',
            'phone': '+60123456786',
            'password': 'shariah456'
        },
        {
            'staff_id': 'credit002',
            'email': 'credit2@smartrisk.com',
            'full_name': 'John Smith',
            'role': UserRole.CREDIT_OFFICER,
            'department': 'Risk Management',
            'phone': '+60123456785',
            'password': 'credit456'
        }
    ]
    
    for user_data in users_data:
        # Check if user already exists
        existing_user = User.query.filter_by(staff_id=user_data['staff_id']).first()
        if existing_user:
            print(f"User {user_data['staff_id']} already exists, skipping...")
            continue
        
        # Create new user
        new_user = User(
            staff_id=user_data['staff_id'],
            email=user_data['email'],
            full_name=user_data['full_name'],
            role=user_data['role'],
            department=user_data['department'],
            phone=user_data['phone'],
            is_active=True,
            is_verified=True,
            created_at=datetime.utcnow()
        )
        new_user.set_password(user_data['password'])
        
        db.session.add(new_user)
        print(f"Created user: {user_data['staff_id']} ({user_data['full_name']})")
    
    db.session.commit()
    print("Default users created successfully!")

def create_sample_data():
    """Create sample data for testing"""
    print("Creating sample data...")
    
    # Sample Loans
    sample_loans = [
        {
            'customer_name': 'Ahmad Sdn Bhd',
            'amount_requested': 500000.00,
            'risk_score': 'Medium Risk',
            'remarks': 'Corporate financing for equipment purchase'
        },
        {
            'customer_name': 'Siti Trading',
            'amount_requested': 250000.00,
            'risk_score': 'Low Risk',
            'remarks': 'Working capital financing'
        },
        {
            'customer_name': 'Tech Innovations',
            'amount_requested': 1000000.00,
            'risk_score': 'High Risk',
            'remarks': 'Startup technology financing'
        }
    ]
    
    for loan_data in sample_loans:
        # Check if loan already exists
        existing_loan = Loan.query.filter_by(customer_name=loan_data['customer_name']).first()
        if existing_loan:
            print(f"Loan for {loan_data['customer_name']} already exists, skipping...")
            continue
            
        loan = Loan(
            customer_name=loan_data['customer_name'],
            amount_requested=loan_data['amount_requested'],
            risk_score=loan_data['risk_score'],
            remarks=loan_data['remarks'],
            application_date=datetime.utcnow().date()
        )
        db.session.add(loan)
    
    # Sample Credit Applications
    sample_credit_apps = [
        {
            'application_id': 'CR001',
            'loan_amount': 500000.00,
            'property_value': 600000.00,
            'monthly_debt': 5000.00,
            'monthly_income': 15000.00,
            'recovery_rate': 80.0,
            'probability_of_default': 15.0,
            'risk_score': 45.5,
            'risk_level': 'Medium'
        },
        {
            'application_id': 'CR002',
            'loan_amount': 300000.00,
            'property_value': 450000.00,
            'monthly_debt': 3000.00,
            'monthly_income': 12000.00,
            'recovery_rate': 85.0,
            'probability_of_default': 10.0,
            'risk_score': 32.8,
            'risk_level': 'Low'
        }
    ]
    
    for credit_data in sample_credit_apps:
        # Check if credit application already exists
        existing_credit = CreditApplication.query.filter_by(application_id=credit_data['application_id']).first()
        if existing_credit:
            print(f"Credit application {credit_data['application_id']} already exists, skipping...")
            continue
            
        credit_app = CreditApplication(**credit_data)
        db.session.add(credit_app)
    
    # Sample Shariah Applications
    sample_shariah_apps = [
        {
            'application_id': 'SH001',
            'application_date': datetime.utcnow().date(),
            'customer_name': 'Halal Food Industries',
            'customer_category': 'Corporate',
            'loan_amount': 750000.00,
            'purpose_of_financing': 'Equipment purchase for halal food production',
            'riba': 'No',
            'gharar': 'No',
            'maysir': 'Absent',
            'business_description': 'Halal food manufacturing company specializing in organic products',
            'shariah_risk_score': 'Halal'
        },
        {
            'application_id': 'SH002',
            'application_date': datetime.utcnow().date(),
            'customer_name': 'Islamic Banking Services',
            'customer_category': 'Corporate',
            'loan_amount': 2000000.00,
            'purpose_of_financing': 'Expansion of Islamic financial services',
            'riba': 'No',
            'gharar': 'No',
            'maysir': 'Absent',
            'business_description': 'Islamic banking and financial services company',
            'shariah_risk_score': 'Halal'
        }
    ]
    
    for shariah_data in sample_shariah_apps:
        # Check if Shariah application already exists
        existing_shariah = ShariahRiskApplication.query.filter_by(application_id=shariah_data['application_id']).first()
        if existing_shariah:
            print(f"Shariah application {shariah_data['application_id']} already exists, skipping...")
            continue
            
        shariah_app = ShariahRiskApplication(**shariah_data)
        db.session.add(shariah_app)
    
    db.session.commit()
    print("Sample data created successfully!")

def create_audit_logs():
    """Create sample audit logs"""
    print("Creating sample audit logs...")
    
    admin_user = User.query.filter_by(staff_id='admin').first()
    
    if admin_user:
        sample_logs = [
            {
                'user_id': admin_user.id,
                'action': 'SYSTEM_INITIALIZED',
                'resource': 'system',
                'details': {'message': 'System database initialized successfully'}
            },
            {
                'user_id': admin_user.id,
                'action': 'USER_CREATED',
                'resource': 'user',
                'resource_id': 'shariah001',
                'details': {'new_user_role': 'shariah_officer'}
            },
            {
                'user_id': admin_user.id,
                'action': 'USER_CREATED',
                'resource': 'user',
                'resource_id': 'credit001',
                'details': {'new_user_role': 'credit_officer'}
            }
        ]
        
        for log_data in sample_logs:
            audit_log = AuditLog(
                user_id=log_data['user_id'],
                action=log_data['action'],
                resource=log_data['resource'],
                resource_id=log_data.get('resource_id'),
                details=log_data.get('details'),
                timestamp=datetime.utcnow()
            )
            db.session.add(audit_log)
        
        db.session.commit()
        print("Sample audit logs created successfully!")

def verify_database_integrity():
    """Verify database integrity and relationships"""
    print("Verifying database integrity...")
    
    # Check user counts
    total_users = User.query.count()
    admin_count = User.query.filter_by(role=UserRole.ADMIN).count()
    shariah_count = User.query.filter_by(role=UserRole.SHARIAH_OFFICER).count()
    credit_count = User.query.filter_by(role=UserRole.CREDIT_OFFICER).count()
    
    print(f"Total users: {total_users}")
    print(f"Admins: {admin_count}")
    print(f"Shariah Officers: {shariah_count}")
    print(f"Credit Officers: {credit_count}")
    
    # Check data counts
    loan_count = Loan.query.count()
    credit_app_count = CreditApplication.query.count()
    shariah_app_count = ShariahRiskApplication.query.count()
    audit_log_count = AuditLog.query.count()
    
    print(f"Loans: {loan_count}")
    print(f"Credit Applications: {credit_app_count}")
    print(f"Shariah Applications: {shariah_app_count}")
    print(f"Audit Logs: {audit_log_count}")
    
    print("Database integrity verification completed!")

def main():
    """Main initialization function"""
    print("=" * 60)
    print("SMART-Risk Database Initialization")
    print("=" * 60)
    
    with app.app_context():
        try:
            # Create all tables
            print("Creating database tables...")
            db.create_all()
            
            # Create default users
            create_default_users()
            
            # Create sample data
            create_sample_data()
            
            # Create audit logs
            create_audit_logs()
            
            # Verify database integrity
            verify_database_integrity()
            
            print("\n" + "=" * 60)
            print("Database initialization completed successfully!")
            print("=" * 60)
            print("\nDefault Login Credentials:")
            print("Admin: admin / admin123")
            print("Shariah Officer: shariah001 / shariah123")
            print("Credit Officer: credit001 / credit123")
            print("=" * 60)
            
        except Exception as e:
            print(f"Error during initialization: {str(e)}")
            db.session.rollback()
            return False
    
    return True

if __name__ == "__main__":
    main()