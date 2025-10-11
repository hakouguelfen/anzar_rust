## Account Suspended
- Every time a request is made check if account is locked           => [DONE]
- If account is locked check if suspension time has been past
- If time has passed -> AcconuntLocked:False -> allow request
- If not return 403:Forbidden

## Password
Password Validation Missing
Add checks before hashing:

## 
Minimum length (12+ characters recommended)
Not in common password lists
Complexity requirements if needed


## RateLimiting
if user failed more then 5 times: Lock account -> [ERROR::AcountLocked]
Limit user from changing password 3 times in 1h -> [ERROR::RateLimitExceeded]

Employ normal security measures, such as SQL Injection Prevention methods and Input Validation.


NOT SURE:
when accessToken is used, check existence of valid refreshToken in DB using jti.
- if not valid, user should be loggedout.


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

