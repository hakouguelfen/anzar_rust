- Employ normal security measures, such as SQL Injection Prevention methods and Input Validation.
- To prevent accidental logging of sensitive information:

## TOADD:
- tests for return type 
- Listen to kill app on syscall SIGTERM
- Retry-After header, after rate limiting

## 4. Global or Behavioral Limits
- Many accounts being hit from one IP.
- Many IPs hitting one account.
- Very short intervals between attempts.
- Then temporarily ban or challenge those sources.


## APIGATEWAY:
- Paramater validation
- Allow/Deny list
- Auth
- Rate Limit
- Route to microservice
- protocol conversion



DoS for specific account

Attackers may cause permanent lockout for all untrusted devices for a specific user. Thus the user may be blocked from loggging into the system as they would need to login from a new device or to login after cleaning up their browser cache.

Issue a valid device cookie after visiting password reset link (an actual password reset is not necessary). Thus, if the user demonstrates their possession of a personal email account then the system may trust a client to try entering their credentials.

