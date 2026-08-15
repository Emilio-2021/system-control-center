# System Control Center

A lightweight ERP-style web application for managing business entities, users, inventory, and sales orders.

## Architecture

```text
User browser
     │
     ▼
FastAPI application (Python)
     │
     ▼
     SQLite database
```

## Features

- Signed, expiring user sessions
- Role-based access control for administrators, operators, and viewers
- User management with bcrypt password hashing
- Person and company customer registry
- Product catalog and inventory tracking
- Checkout workflow with stock locking and order creation
- Order and line-item history
- Dashboard metrics

## Technology stack

- Python 3.11+
- FastAPI
- Jinja2 templates
- SQLite
- SQLAlchemy
- bcrypt
- Bootstrap

## Local setup

1. Create and activate a virtual environment.

2. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

3. Set a long random `SESSION_SECRET` in your environment. The default local database is `database.db`.

4. Start the application:

   ```powershell
   uvicorn main:app --reload
   ```

Open `http://127.0.0.1:8000` in a browser.

## Database

The application uses the local SQLite database `database.db`. `seed_db.py` can populate test users and entities after the schema has been created:

The database file is intentionally ignored by Git because it contains local data. A prepared `database.db` must exist locally before running the application.

```powershell
python seed_db.py
```

The seed script creates these test accounts:

- `admin` / `admin123`
- `manager` / `manager123`

Do not use these credentials in production.

To add sample inventory without resetting existing data, run:

```powershell
python seed_products.py
```

Products are matched by SKU, so running the script again refreshes the sample product records.

## Configuration

Configuration is read from environment variables:

```text
DATABASE_URL=sqlite:///database.db
SESSION_SECRET=replace-with-a-long-random-secret
ENVIRONMENT=development
```

Never commit `.env` or production credentials to source control.

## Main routes

| Route | Purpose |
| --- | --- |
| `/` | Login page |
| `/dashboard` | Dashboard |
| `/users-view` | User management |
| `/entities-view` | Entity management |
| `/products-view` | Inventory management |
| `/checkout` | Create an order |
| `/orders-view` | View order history |

## Roles

- `admin`: manage users, entities, products, and orders
- `operator`: view business data and create checkout orders
- `viewer`: read-only access to dashboards and business data
