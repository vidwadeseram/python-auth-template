Used dedicated verification_service.py and password_reset_service.py files, with auth_service delegating to them to preserve existing router/service patterns.
Removed RBAC compatibility shim files from the branch so the branch diff stays focused on extended auth only.
