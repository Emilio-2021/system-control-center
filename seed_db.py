import bcrypt
from sqlalchemy import text
from database import SessionLocal

def seed_database():
    db = SessionLocal()
    try:
        print("Starting database clean-up and seeding process...")

        # 1. Clear local test data. The project uses SQLite, so use DELETE
        # rather than PostgreSQL-only TRUNCATE syntax.
        db.execute(text("DELETE FROM users"))
        db.execute(text("DELETE FROM entities"))
        
        # 2. Generate secure bcrypt hashes for our test users
        salt = bcrypt.gensalt()
        admin_hash = bcrypt.hashpw("admin123".encode('utf-8'), salt).decode('utf-8')
        manager_hash = bcrypt.hashpw("manager123".encode('utf-8'), salt).decode('utf-8')

        # 3. Seed Users
        print("Seeding users...")
        users_sql = text("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES (:user1, :email1, :hash1, 'admin'), (:user2, :email2, :hash2, 'operator');
        """)
        db.execute(users_sql, {
            "user1": "admin", "email1": "admin@system.local", "hash1": admin_hash,
            "user2": "manager", "email2": "manager@system.local", "hash2": manager_hash
        })

        # 4. Seed Entities using the lookup-table IDs.
        print("Seeding business entities...")
        person_type = db.execute(text(
            "SELECT id FROM entity_type WHERE UPPER(entity) = 'PERSON'"
        )).scalar()
        company_type = db.execute(text(
            "SELECT id FROM entity_type WHERE UPPER(entity) = 'COMPANY'"
        )).scalar()
        if person_type is None or company_type is None:
            raise RuntimeError("entity_type lookup table is missing PERSON or COMPANY")
        entities_sql = text("""
            INSERT INTO entities (entity_type, name, email) 
            VALUES (:person_type, 'Jordan Smith', 'jordan@example.com'),
                   (:company_type, 'AdventureWorks Cycles', 'info@adventureworks.com'),
                   (:company_type, 'Global Logistics Partners', 'shipping@globallogistics.net');
        """)
        db.execute(entities_sql, {"person_type": person_type, "company_type": company_type})

        # 5. Fetch a valid entity ID to connect tasks safely
        entity_id = db.execute(text("SELECT id FROM entities LIMIT 1;")).scalar()

        # 6. Commit changes to SQLite
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
