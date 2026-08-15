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
- Delete operations use authenticated `POST` requests.

## Deployment requirements

- Set a long, random `SESSION_SECRET` in production.
- Set `ENVIRONMENT=production` so cookies use the `Secure` flag.
- Protect the local SQLite database file with appropriate filesystem permissions.
- Store secrets in the hosting provider's environment configuration.
- Do not commit `.env`, database URLs, or seed credentials.
- Replace the development seed passwords before deployment.

## Remaining production hardening

- Add CSRF tokens to all state-changing forms.
- Add rate limiting and account lockout for login attempts.
- Return generic user-facing database errors while logging detailed server-side diagnostics.
- Add automated tests for authentication, authorization, checkout transactions, and inventory races.
