Implemented email verification and password reset as token-table backed flows while keeping existing auth router intact.
Verified the full flow with docker-compose, MailHog token extraction, verify-email, forgot-password, reset-password, and login with the new password.
