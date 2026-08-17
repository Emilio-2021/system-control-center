# Project Status

## Current state

The FastAPI ERP portfolio application is working locally with:

- Signed, expiring sessions and protected application routes
- Role-based access control for administrators, operators, and viewers
- User management with bcrypt passwords
- `PERSON` and `COMPANY` entity types
- Inventory product management
- Checkout and order creation
- Inventory deduction during checkout
- Order history display
- Individual order details and full refund processing
- Dashboard recent-order summary with direct links to order details
- Dashboard entity summary and navigation
- Centralized rotating database support log at `logs/log.txt`
- Sample product data through `seed_products.py`

## Useful commands

```powershell
uvicorn main:app --reload
python seed_products.py
python -m py_compile main.py
Get-Content logs\log.txt -Tail 50
```

## Database setup

- Configure `DATABASE_URL` and `SESSION_SECRET` using `.env` or the hosting provider environment.
- The local database is SQLite (`database.db`); the role column is added automatically to an existing local database.
- `database.db` is intentionally excluded from GitHub because it contains local application data.
- A prepared SQLite database must be supplied locally before starting the application.
- Do not run `seed_db.py` against important data; it clears and replaces local users and entities.
- Database operations are recorded in `logs/log.txt`; bound parameter values are excluded from those entries.

## Portfolio readiness

The project is suitable as a portfolio demonstration. Recommended next work before production deployment:

1. Add automated tests for authentication, authorization, checkout, and inventory changes.
2. Add screenshots or a short demo GIF to `README.md`.
3. Add CSRF protection before production deployment.
4. Add rate limiting and account lockout for login attempts.
5. Review and remove older duplicate documentation/template files.
