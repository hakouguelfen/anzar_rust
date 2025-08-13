*Phase 1: Reset Request
1. Extract & normalize email[DONE]
2. Check IP rate limiting
3. Check if email exists (constant time response)[DONE]
4. If exists: check user-based rate limiting
5. If exists: invalidate existing tokens
6. If exists: generate new token + hash[DONE]
7. If exists: store token record[DONE]
8. If exists: send email[DONE]
9. Always: return success message[DONE]
10. Log attempt (without revealing email existence)


Phase 2: Token Validation
1. Extract token from URL
2. Validate token format
3. Hash token for database lookup
4. Check token exists & valid
5. Check token not expired
6. Check token not used
7. Check user account active
8. Log validation attempt
9. Return validation result

Phase 3: Password Reset
BEGIN TRANSACTION
  1. Re-validate token (prevent race conditions)
  2. Validate new password strength
  3. Check new password ≠ current password
  4. Hash new password
  5. Update user.password_hash
  6. Mark token as used (used_at = now)
  7. Invalidate all other user tokens
  8. Clear all user sessions
  9. Update user.last_password_change
  10. Reset user.failed_login_attempts
COMMIT TRANSACTION

11. Send confirmation email
12. Log successful password change
13. Return success response




## RateLimiting
if user failed more then 5 times: Lock account -> [ERROR::AcountLocked]
Limit user from changing password 3 times in 1h -> [ERROR::RateLimitExceeded]



RefreshToken:
- Decode JWT, get jti.
- if valid jti exist in DB -> invalidate and rotate
- if not -> user is loggedOut

Logout:
- Send refreshToken
- find refreshToken in DB and invalidate it


NOT SURE:
when accessToken is used, check existence of valid refreshToken in DB using jti.
- if not valid, user should be loggedout.
