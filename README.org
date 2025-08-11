** Environment Variables

The following environment variables are required:

+ `JWT_ACCESS_TOKEN_SECRET`: Secret for signing JWT access tokens
+ `JWT_REFRESH_TOKEN_SECRET`: Secret for signing JWT refresh tokens
+ `DATABASE_URI`: Secret for Database url

These should be set using a .env file or passed directly when running the container.

** Resources
# https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
# https://www.loginradius.com/blog/identity/refresh-tokens-jwt-interaction/
# https://www.shuttle.rs/blog/2024/02/21/using-jwt-auth-rust

** To run

```bash
APP_ENVIRONMENT=local cargo test
```
