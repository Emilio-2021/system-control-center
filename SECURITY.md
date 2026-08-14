# Security Notes

## Current protections

- Passwords are stored using bcrypt hashes.
- Session cookies are signed with `SESSION_SECRET` and expire after eight hours.
- Session cookies use `HttpOnly` and `SameSite=Lax`; production deployments also use `Secure`.
- Protected routes require a valid session and an existing database user.
- SQL identifiers accepted from forms are restricted to explicit allowlists.
- Inventory updates lock product rows during checkout.
- Delete operations use authenticated `POST` requests.

## Deployment requirements

- Set a long, random `SESSION_SECRET` in production.
- Set `ENVIRONMENT=production` so cookies use the `Secure` flag.
- Use a restricted PostgreSQL account instead of the database superuser.
- Store secrets in the hosting provider's environment configuration.
- Do not commit `.env`, database URLs, or seed credentials.
- Replace the development seed passwords before deployment.

## Remaining production hardening

- Add CSRF tokens to all state-changing forms.
- Add role-based authorization so ordinary users cannot administer all records.
- Add rate limiting and account lockout for login attempts.
- Return generic user-facing database errors while logging detailed server-side diagnostics.
- Add automated tests for authentication, authorization, checkout transactions, and inventory races.
