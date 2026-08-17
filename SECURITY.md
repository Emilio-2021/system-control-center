# Security Notes

## Current protections

- Passwords are stored using bcrypt hashes.
- Session cookies are signed with `SESSION_SECRET` and expire after eight hours.
- Session cookies use `HttpOnly` and `SameSite=Lax`; production deployments also use `Secure`.
- Protected routes require a valid session and an existing database user.
- Role-based access restricts user management and catalog changes to administrators.
- Operators can process checkout transactions; viewers have read-only access.
- SQL identifiers accepted from forms are restricted to explicit allowlists.
- Inventory updates are atomic during checkout to prevent overselling.
- Refunds are recorded separately, restore inventory once, and preserve the original order history.
- Full refunds are available only to administrators and operators; read-only users can review orders.
- Delete operations use authenticated `POST` requests.
- Database support logging excludes SQLAlchemy bound parameter values to reduce the risk of recording passwords or submitted form data.

## Deployment requirements

- Set a long, random `SESSION_SECRET` in production.
- Set `ENVIRONMENT=production` so cookies use the `Secure` flag.
- Protect the local SQLite database file with appropriate filesystem permissions.
- Protect `logs/log.txt` with appropriate filesystem permissions because SQL statements and operational diagnostics may still reveal application structure.
- Store secrets in the hosting provider's environment configuration.
- Do not commit `.env`, database URLs, or seed credentials.
- Replace the development seed passwords before deployment.

## Remaining production hardening

- Add CSRF tokens to all state-changing forms.
- Add rate limiting and account lockout for login attempts.
- Return generic user-facing database errors while logging detailed server-side diagnostics.
- Add automated tests for authentication, authorization, checkout transactions, and inventory races.
