# Project Status

## Current state

The FastAPI ERP portfolio application is working locally with:

- Signed, expiring sessions and protected application routes
- User management with bcrypt passwords
- `PERSON` and `COMPANY` entity types
- Inventory product management
- Checkout and order creation
- Inventory deduction during checkout
- Order history display
- Dashboard entity summary and navigation
- Sample product data through `seed_products.py`

## Useful commands

```powershell
uvicorn main:app --reload
python seed_products.py
python -m py_compile main.py
```

## Database setup

- Configure `DATABASE_URL` and `SESSION_SECRET` using `.env` or the hosting provider environment.
- Run `migrations/001_person_company_entities.sql` against an existing database.
- The migration changes legacy `CLIENT` and `AGENCY` values to `PERSON` and `COMPANY`.
- Do not run `seed_db.py` against important data; it truncates several tables.

## Portfolio readiness

The project has an initial local Git commit and is ready for further cleanup before publishing to GitHub. Recommended next work:

1. Add the PostgreSQL schema or a reproducible database setup script.
2. Add automated tests for authentication, checkout, and inventory changes.
3. Add screenshots or a short demo GIF to `README.md`.
4. Add CSRF protection and role-based authorization before production deployment.
5. Review and remove the older duplicate documentation/template files.

