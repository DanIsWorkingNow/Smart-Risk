# test_connection.py
import psycopg2

try:
    # Test connection to PostgreSQL
    print("🔍 Testing PostgreSQL connection...")
    
    # Replace 'your_postgres_password' with the actual password you set during PostgreSQL installation
    conn = psycopg2.connect(
        host="localhost",
        database="postgres",  # default database
        user="postgres",
        password="PostGres0725!",  # ⚠️ CHANGE THIS to your actual password
        port="5432"
    )
    
    cursor = conn.cursor()
    cursor.execute("SELECT version();")
    version = cursor.fetchone()
    
    print("✅ PostgreSQL connection successful!")
    print(f"✅ PostgreSQL version: {version[0]}")
    
    # Test if smart_risk_db exists
    cursor.execute("SELECT datname FROM pg_database WHERE datname = 'smart_risk_db';")
    db_exists = cursor.fetchone()
    
    if db_exists:
        print("✅ smart_risk_db database exists!")
    else:
        print("⚠️ smart_risk_db database not found - need to create it")
    
    cursor.close()
    conn.close()
    
except psycopg2.OperationalError as e:
    print(f"❌ Connection failed: {e}")
    print("💡 Check your PostgreSQL password and make sure PostgreSQL is running")
    
except Exception as e:
    print(f"❌ Unexpected error: {e}")