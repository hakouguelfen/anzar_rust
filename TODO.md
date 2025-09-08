## Account Suspended
- Every time a request is made check if account is locked
- If account is locked check if suspension time has been past
- If time has passed -> AcconuntLocked:False -> allow request
- If not return 403:Forbidden


## DB Mongo
- Don't return Option, return Result
- Option hides the implications of process, Mongo may not change an already changed doc and this will successed but will return None
- Result will only return ERROR when there is DB Error which is recommended



## RateLimiting
if user failed more then 5 times: Lock account -> [ERROR::AcountLocked]
Limit user from changing password 3 times in 1h -> [ERROR::RateLimitExceeded]

## TOADD:
- validator [DONE]
- tests for return type 
- Listen to kill app on syscall SIGTERM


## APIGATEWAY:
- Paramater validation
- Allow/Deny list
- Auth
- Rate Limit
- Route to microservice
- protocol conversion


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
