"""Insert or refresh sample inventory products for local testing."""

from sqlalchemy import text

from database import SessionLocal


PRODUCTS = [
    ("Wireless Keyboard", "KB-WL-001", 29.99, 42),
    ("Ergonomic Mouse", "MS-ER-002", 24.50, 65),
    ("USB-C Docking Station", "DK-USBC-003", 89.95, 18),
    ("27-inch Office Monitor", "MN-27-004", 219.00, 12),
    ("Noise-Cancelling Headset", "HS-NC-005", 74.99, 27),
    ("Laptop Stand", "LS-AL-006", 39.95, 34),
    ("USB-C Cable 2m", "CB-USBC-007", 12.99, 100),
    ("Portable SSD 1TB", "SSD-1T-008", 109.99, 16),
]


def seed_products() -> None:
    db = SessionLocal()
    try:
        for name, sku, price, stock_quantity in PRODUCTS:
            db.execute(
                text("""
                    INSERT INTO products (name, sku, price, stock_quantity)
                    VALUES (:name, :sku, :price, :stock_quantity)
                    ON CONFLICT (sku) DO UPDATE SET
                        name = EXCLUDED.name,
                        price = EXCLUDED.price,
                        stock_quantity = EXCLUDED.stock_quantity
                """),
                {
                    "name": name,
                    "sku": sku,
                    "price": price,
                    "stock_quantity": stock_quantity,
                },
            )
        db.commit()
        print(f"Seeded {len(PRODUCTS)} sample products.")
    except Exception as exc:
        db.rollback()
        print(f"Failed to seed products: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_products()
