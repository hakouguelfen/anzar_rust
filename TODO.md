Account activation via email verification [DONE]
account lockouts after failed attempts [DONE]

SQL injection and XSS prevention
Middleware/guards to protect routes requiring authentication
CSRF protection for form submissions

Employ normal security measures, such as SQL Injection Prevention methods and Input Validation.


## Password
Password Validation Missing
Add checks before hashing:
### 
Minimum length (12+ characters recommended)
Not in common password lists
Complexity requirements if needed


## RateLimiting
if user failed more then 5 times: Lock account -> [ERROR::AcountLocked]
Limit user from changing password 3 times in 1h -> [ERROR::RateLimitExceeded]




## TOADD:
- tests for return type 
- Listen to kill app on syscall SIGTERM


## APIGATEWAY:
- Paramater validation
- Allow/Deny list
- Auth
- Rate Limit
- Route to microservice
- protocol conversion

