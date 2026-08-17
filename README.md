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
- Individual order details and transactional full refunds
- Dashboard recent-order links with contextual navigation back to the originating page
- Dashboard metrics
- Centralized database operation logging for support diagnostics

The refund workflow is available from a completed order's detail page. Administrators and operators can issue one full refund with a reason; the system records the refund, restores the ordered inventory, and marks the order as `REFUNDED`. Viewer accounts can review refund details but cannot issue refunds.

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

The application uses the local SQLite database `database.db`. The database file is intentionally ignored by Git because it contains local application data, user password hashes, and business records. A prepared database must exist locally before starting the application.

Create administrator and other application users with secure, unique passwords before deployment. Do not commit database files or credentials to source control.

## Support logging

Database activity is written to `logs/log.txt` when the application or a database utility starts. Each entry includes the timestamp, operation type, duration, row count, SQL statement, and any database error. SQLAlchemy bound parameter values are intentionally excluded so passwords and submitted form values are not recorded.

The log rotates after 5 MB and keeps up to three backup files. The `logs/` directory is created automatically, and log files are excluded from Git because they may contain operational details.

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
| `/orders/{order_id}` | View an individual order and process a full refund |
| `POST /orders/{order_id}/refund` | Record a full refund, restore inventory, and mark the order refunded |

## Roles

- `admin`: manage users, entities, products, and orders
- `operator`: view business data and create checkout orders
- `viewer`: read-only access to dashboards and business data
