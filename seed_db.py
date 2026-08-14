import bcrypt
from sqlalchemy import text
from database import SessionLocal

def seed_database():
    db = SessionLocal()
    try:
        print("Starting database clean-up and seeding process...")

        # 1. Clear old testing data safely to prevent unique constraint failures
        db.execute(text("TRUNCATE TABLE audit_logs, tasks, users, entities RESTART IDENTITY CASCADE;"))
        
        # 2. Generate secure bcrypt hashes for our test users
        salt = bcrypt.gensalt()
        admin_hash = bcrypt.hashpw("admin123".encode('utf-8'), salt).decode('utf-8')
        manager_hash = bcrypt.hashpw("manager123".encode('utf-8'), salt).decode('utf-8')

        # 3. Seed Users
        print("Seeding users...")
        users_sql = text("""
            INSERT INTO users (username, email, password_hash) 
            VALUES (:user1, :email1, :hash1), (:user2, :email2, :hash2);
        """)
        db.execute(users_sql, {
            "user1": "admin", "email1": "admin@system.local", "hash1": admin_hash,
            "user2": "manager", "email2": "manager@system.local", "hash2": manager_hash
        })

        # 4. Seed Entities (Clients and Agencies)
        print("Seeding business entities...")
        entities_sql = text("""
            INSERT INTO entities (entity_type, name, email) 
            VALUES ('PERSON', 'Jordan Smith', 'jordan@example.com'),
                   ('COMPANY', 'AdventureWorks Cycles', 'info@adventureworks.com'),
                   ('COMPANY', 'Global Logistics Partners', 'shipping@globallogistics.net');
        """)
        db.execute(entities_sql)

        # 5. Fetch a valid entity ID to connect tasks safely
        entity_id = db.execute(text("SELECT id FROM entities LIMIT 1;")).scalar()

        # 6. Commit changes to PostgreSQL
        db.commit()
        print("🎉 Database successfully initialized and seeded with test data!")
        print("👉 You can now log into your web dashboard using: admin / admin123")

    except Exception as e:
        db.rollback()
        print(f"❌ Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
