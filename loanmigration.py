#!/usr/bin/env python3
"""
Loan Database Migration Script
Migrates the existing simple loans table to a comprehensive banking-standard structure
"""

import sys
import os
from datetime import datetime

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
    from sqlalchemy import text
except ImportError as e:
    print(f"Error importing app modules: {e}")
    sys.exit(1)

def backup_existing_data():
    """Backup existing loan data before migration"""
    
    with app.app_context():
        try:
            # Check if loans table exists and has data
            result = db.session.execute(text("SELECT COUNT(*) FROM loans"))
            count = result.scalar()
            
            if count > 0:
                print(f"📦 Found {count} existing loan records. Creating backup...")
                
                # Create backup table
                db.session.execute(text("""
                    CREATE TABLE IF NOT EXISTS loans_backup AS 
                    SELECT * FROM loans
                """))
                
                print("✅ Backup created as 'loans_backup' table")
                return True
            else:
                print("📝 No existing data to backup")
                return False
                
        except Exception as e:
            print(f"⚠️ Backup error (table might not exist): {e}")
            return False

def drop_existing_table():
    """Drop the existing loans table"""
    
    with app.app_context():
        try:
            db.session.execute(text("DROP TABLE IF EXISTS loans"))
            db.session.commit()
            print("🗑️ Existing loans table dropped")
        except Exception as e:
            print(f"❌ Error dropping table: {e}")

def create_new_loan_table():
    """Create the new comprehensive loan table"""
    
    with app.app_context():
        try:
            # Create comprehensive loans table
            create_table_sql = """
            CREATE TABLE loans (
                -- Primary Key
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                
                -- Application Details
                application_id VARCHAR(50) UNIQUE NOT NULL,
                application_date DATE NOT NULL,
                branch_code VARCHAR(10),
                
                -- Customer Information
                ic_number VARCHAR(20) NOT NULL,
                customer_name VARCHAR(200) NOT NULL,
                phone VARCHAR(20),
                email VARCHAR(100),
                customer_type VARCHAR(20) DEFAULT 'individual',
                address TEXT,
                
                -- Financing Details
                product_type VARCHAR(50) NOT NULL,
                amount_requested DECIMAL(15,2) NOT NULL,
                loan_term_months INTEGER,
                interest_rate DECIMAL(5,2),
                purpose_of_financing VARCHAR(100),
                currency VARCHAR(5) DEFAULT 'MYR',
                
                -- Calculated Fields
                monthly_payment DECIMAL(15,2),
                total_interest DECIMAL(15,2),
                total_payment DECIMAL(15,2),
                
                -- Financial Information
                monthly_income DECIMAL(15,2),
                existing_commitments DECIMAL(15,2),
                employment_type VARCHAR(50),
                
                -- Collateral Information
                collateral_type VARCHAR(50),
                collateral_value DECIMAL(15,2),
                ltv_ratio DECIMAL(5,2),
                
                -- Additional Information
                business_description TEXT,
                remarks TEXT,
                risk_category VARCHAR(20) DEFAULT 'medium',
                priority VARCHAR(20) DEFAULT 'normal',
                relationship_manager VARCHAR(100),
                
                -- Status and Workflow
                status VARCHAR(50) DEFAULT 'pending',
                risk_score VARCHAR(50),
                credit_score INTEGER,
                approval_status VARCHAR(50) DEFAULT 'pending',
                approved_amount DECIMAL(15,2),
                
                -- Audit Fields
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_by INTEGER,
                approved_at TIMESTAMP,
                
                -- Foreign Key Constraints
                FOREIGN KEY (created_by) REFERENCES users (id),
                FOREIGN KEY (updated_by) REFERENCES users (id),
                FOREIGN KEY (approved_by) REFERENCES users (id)
            )
            """
            
            db.session.execute(text(create_table_sql))
            db.session.commit()
            print("✅ New comprehensive loans table created")
            
        except Exception as e:
            print(f"❌ Error creating new table: {e}")
            raise

def migrate_existing_data():
    """Migrate data from backup table to new structure"""
    
    with app.app_context():
        try:
            # Check if backup table exists
            result = db.session.execute(text("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='loans_backup'
            """))
            
            if result.fetchone():
                # Migrate basic data from backup
                migrate_sql = """
                INSERT INTO loans (
                    application_id, customer_name, amount_requested, 
                    remarks, created_at, application_date, 
                    product_type, status, risk_score
                )
                SELECT 
                    'LA' || strftime('%Y%m%d%H%M', created_at) || SUBSTR('000' || id, -3, 3) as application_id,
                    customer_name,
                    amount_requested,
                    remarks,
                    created_at,
                    date(created_at) as application_date,
                    'murabaha' as product_type,
                    'pending' as status,
                    COALESCE(risk_score, 'Medium Risk') as risk_score
                FROM loans_backup
                """
                
                db.session.execute(text(migrate_sql))
                db.session.commit()
                
                # Count migrated records
                result = db.session.execute(text("SELECT COUNT(*) FROM loans"))
                count = result.scalar()
                print(f"✅ Migrated {count} records to new structure")
            else:
                print("📝 No backup data to migrate")
                
        except Exception as e:
            print(f"❌ Error migrating data: {e}")

def create_sample_data():
    """Create sample loan data for testing"""
    
    with app.app_context():
        try:
            sample_loans = [
                {
                    'application_id': 'LA202406180001',
                    'application_date': '2024-06-18',
                    'branch_code': 'KL001',
                    'ic_number': '901201-14-5678',
                    'customer_name': 'Ahmad Bin Abdullah',
                    'phone': '+60123456789',
                    'email': 'ahmad@email.com',
                    'customer_type': 'individual',
                    'address': 'No. 123, Jalan Merdeka, 50000 Kuala Lumpur',
                    'product_type': 'murabaha',
                    'amount_requested': 250000.00,
                    'loan_term_months': 240,
                    'interest_rate': 8.50,
                    'purpose_of_financing': 'home_purchase',
                    'currency': 'MYR',
                    'monthly_payment': 2156.25,
                    'total_interest': 267500.00,
                    'total_payment': 517500.00,
                    'monthly_income': 8000.00,
                    'existing_commitments': 1500.00,
                    'employment_type': 'permanent',
                    'collateral_type': 'property',
                    'collateral_value': 350000.00,
                    'ltv_ratio': 90.0,
                    'business_description': 'Primary residence purchase',
                    'risk_category': 'low',
                    'priority': 'normal',
                    'status': 'pending',
                    'approval_status': 'pending'
                },
                {
                    'application_id': 'LA202406180002',
                    'application_date': '2024-06-18',
                    'branch_code': 'PJ002',
                    'ic_number': '850315-08-1234',
                    'customer_name': 'Siti Nurhaliza Binti Hassan',
                    'phone': '+60198765432',
                    'email': 'siti@email.com',
                    'customer_type': 'sme',
                    'address': 'No. 456, Jalan PJ, 47100 Petaling Jaya',
                    'product_type': 'musharakah',
                    'amount_requested': 500000.00,
                    'loan_term_months': 84,
                    'interest_rate': 9.25,
                    'purpose_of_financing': 'business_expansion',
                    'currency': 'MYR',
                    'monthly_payment': 7250.50,
                    'total_payment': 609042.00,
                    'monthly_income': 15000.00,
                    'existing_commitments': 3000.00,
                    'employment_type': 'business_owner',
                    'collateral_type': 'property',
                    'collateral_value': 800000.00,
                    'ltv_ratio': 62.5,
                    'business_description': 'Expansion of halal food manufacturing business',
                    'risk_category': 'medium',
                    'priority': 'high',
                    'status': 'approved',
                    'approval_status': 'approved',
                    'approved_amount': 450000.00
                },
                {
                    'application_id': 'LA202406180003',
                    'application_date': '2024-06-18',
                    'branch_code': 'SB003',
                    'ic_number': '921212-05-9876',
                    'customer_name': 'Raj Kumar A/L Subramaniam',
                    'phone': '+60167894561',
                    'email': 'raj@email.com',
                    'customer_type': 'individual',
                    'address': 'No. 789, Jalan Shah Alam, 40000 Shah Alam',
                    'product_type': 'tawarruq',
                    'amount_requested': 75000.00,
                    'loan_term_months': 60,
                    'interest_rate': 8.25,
                    'purpose_of_financing': 'education',
                    'currency': 'MYR',
                    'monthly_payment': 1520.30,
                    'total_payment': 91218.00,
                    'monthly_income': 6000.00,
                    'existing_commitments': 800.00,
                    'employment_type': 'permanent',
                    'business_description': 'Masters degree in Engineering',
                    'risk_category': 'low',
                    'priority': 'normal',
                    'status': 'under_review',
                    'approval_status': 'pending'
                }
            ]
            
            for loan_data in sample_loans:
                columns = ', '.join(loan_data.keys())
                placeholders = ', '.join([f":{key}" for key in loan_data.keys()])
                insert_sql = f"INSERT INTO loans ({columns}) VALUES ({placeholders})"
                
                db.session.execute(text(insert_sql), loan_data)
            
            db.session.commit()
            print(f"✅ Created {len(sample_loans)} sample loan records")
            
        except Exception as e:
            print(f"❌ Error creating sample data: {e}")

def verify_migration():
    """Verify the migration was successful"""
    
    with app.app_context():
        try:
            # Count total records
            result = db.session.execute(text("SELECT COUNT(*) FROM loans"))
            total_count = result.scalar()
            
            # Count by status
            result = db.session.execute(text("""
                SELECT status, COUNT(*) as count 
                FROM loans 
                GROUP BY status
            """))
            status_counts = result.fetchall()
            
            print("\n📊 Migration Verification:")
            print(f"   Total loan records: {total_count}")
            print("   Status breakdown:")
            for status, count in status_counts:
                print(f"     - {status}: {count}")
            
            # Show sample data
            result = db.session.execute(text("""
                SELECT application_id, customer_name, amount_requested, status, product_type
                FROM loans 
                LIMIT 3
            """))
            sample_data = result.fetchall()
            
            print("\n📋 Sample Records:")
            for record in sample_data:
                print(f"   {record[0]} - {record[1]} - RM{record[2]:,.2f} - {record[3]} - {record[4]}")
            
        except Exception as e:
            print(f"❌ Verification error: {e}")

def main():
    """Main migration function"""
    
    print("🏦 SMART-Risk Loan Database Migration")
    print("=" * 50)
    
    print("\n1️⃣ Backing up existing data...")
    backup_created = backup_existing_data()
    
    print("\n2️⃣ Dropping existing table...")
    drop_existing_table()
    
    print("\n3️⃣ Creating new comprehensive table...")
    create_new_loan_table()
    
    if backup_created:
        print("\n4️⃣ Migrating existing data...")
        migrate_existing_data()
    
    print("\n5️⃣ Creating sample data...")
    create_sample_data()
    
    print("\n6️⃣ Verifying migration...")
    verify_migration()
    
    print("\n✅ Migration completed successfully!")
    print("\n💡 Next steps:")
    print("   1. Update your Loan model in app.py")
    print("   2. Create 'View Loans' page")
    print("   3. Add navigation menu item")
    print("   4. Test the loan creation form")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("Please check the error and try again.")
        sys.exit(1)