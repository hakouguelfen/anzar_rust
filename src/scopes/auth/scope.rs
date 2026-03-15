use actix_web::{
    HttpResponse, Scope,
    middleware::from_fn,
    web::{self},
};

use validator::{Validate, ValidateArgs};

use crate::extractors::{AuthServiceExtractor, ConfigurationExtractor, ValidatedQuery};
use crate::middlewares::{auth_middleware, authorization_middleware, rate_limiting::RATE_LIMITS};
use crate::{
    config::AuthStrategy,
    error::{CredentialField, Error, ErrorResponse, FailureReason, Result},
    utils::HmacSigner,
};

use crate::services::{
    account::{model::AccountStatus, service::AccountServiceTrait},
    jwt::service::JwtServiceTrait,
    session::{model::Session, service::SessionServiceTrait},
};
use crate::utils::{CustomPasswordHasher, Password, Token, TokenHasher};

use super::models::{
    AuthResponse, EmailRequest, LoginRequest, RefreshTokenRequest, RegisterRequest, ResetLink,
    ResetPasswordRequest, TokenQuery,
};
use super::reset_password::{model::PasswordResetToken, service::PasswordResetTokenServiceTrait};
use super::user::{User, service::UserServiceTrait};

use super::support;

#[utoipa::path(
        post,
        path = "/auth/login",
        tag = "Auth",
        summary = "User login",
        description = "Authenticates a user with email and password.\n\n\
            **Session strategy**: Returns a session cookie (`id`) managed by the server.\n\
            **JWT strategy**: Returns `access` and `refresh` in the response body.",
        request_body(
            description = "User login credentials",
            content = LoginRequest
        ),
        responses(
            (
                status = 200,
                description = "User logged successfully",
                body = AuthResponse,
                headers(
                    ("Set-Cookie" = String,
                     description = "Session cookie (session strategy only). \
                     HttpOnly, Secure, SameSite=Strict. \
                                Format: id=<session_id>; HttpOnly; Secure; SameSite=Strict")
                )
            ),
            (status = BAD_REQUEST, description = "Invalid request", body = ErrorResponse),
            (status = UNAUTHORIZED, description = "Invalid credentials", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(
    name = "Login user",
    skip(req, auth_service, configuration, session),
    fields(user_email = %req.email)
)]
pub async fn login(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    req: web::Json<LoginRequest>,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    req.validate_with_args(&configuration.auth.password.requirements)
        .map_err(|e| Error::BadRequest(e.to_string()))?;

    // START TIMING-SAFE EXECUTION BLOCK
    let start = std::time::Instant::now();

    let mut hmac_signer = HmacSigner::new(&configuration.security.secret_key);

    // ALWAYS execute the same operations regardless of user existence
    let (user, account_status, attempts) = auth_service
        .authenticate_user(
            &req.email,
            &req.password,
            &hmac_signer,
            &session,
            &configuration,
        )
        .await?;

    // ENFORCE CONSTANT-TIME EXECUTION
    support::throttle_since(start).await;

    // Now handle responses
    match account_status {
        AccountStatus::Active => {
            // Issue new device cookie
            tracing::info!("user logged in");
            let cookie = hmac_signer.issue(&req.email);

            match configuration.auth.strategy {
                AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
                    session.clear();
                    session.renew();
                    session.insert(support::DEVICE_COOKIE, &cookie)?;
                    session.insert(support::SESSION_COOKIE, token)?;
                    Ok(HttpResponse::Ok().json(AuthResponse::new(user)))
                })?,
                AuthStrategy::Jwt => {
                    auth_service
                        .issue_jwt(&user, &configuration)
                        .await
                        .map(|tokens| {
                            session.clear();
                            session.renew();
                            session.insert(support::DEVICE_COOKIE, &cookie)?;

                            Ok(HttpResponse::Ok().json(
                                AuthResponse::new(user)
                                    .with_jwt(tokens, configuration.auth.jwt.expires_in),
                            ))
                        })?
                }
            }
        }
        // NOTE fully mask account existence
        // only return InvalidCredentials
        AccountStatus::Unverified => Err(Error::AccountNotVerified {
            field: CredentialField::Email,
        }),
        AccountStatus::Suspended => Err(Error::AccountSuspended {}),
        _ => {
            support::delay(attempts as u32).await;
            return Err(Error::InvalidCredentials {
                field: CredentialField::EmailOrPassword,
                reason: FailureReason::Any,
            });
        }
    }
}

#[utoipa::path(
        post,
        path = "/auth/register",
        tag = "Auth",
        summary = "Register a new user",
        description = "Creates a new user account with email and password.\n\n\
            **Session strategy**: Returns a session cookie (`id`) managed by the server.\n\
            **JWT strategy**: Returns `access` and `refresh` in the response body.",
        request_body(
            description = "User register credentials",
            content = RegisterRequest
        ),
        responses(
            (
                status = 201,
                description = "User registerd successfully",
                body = AuthResponse,
                headers(
                    ("Set-Cookie" = String,
                     description = "Session cookie (session strategy only). \
                     HttpOnly, Secure, SameSite=Strict. \
                                Format: id=<session_id>; HttpOnly; Secure; SameSite=Strict")
                )
            ),
            (status = BAD_REQUEST, description = "Invalid request", body = ErrorResponse),
            (status = UNAUTHORIZED, description = "Invalid credentials", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(
    name = "Register user",
    skip(req, auth_service, configuration, session),
    fields(user_email = %req.email, user_name = %req.username)
)]
pub async fn register(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    req: web::Json<RegisterRequest>,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    req.validate_with_args(&configuration.auth.password.requirements)
        .map_err(|err| Error::BadRequest(err.to_string()))?;

    // let mut bucket = RATE_LIMITS.entry(email.clone()).or_default();
    // bucket.run()?;

    let user = auth_service.create_user(req.into_inner()).await?;

    let email_config = &configuration.auth.email;
    if email_config.verification.required {
        let email_verification_expiry = email_config.verification.token_expires_in;

        let verification_token = auth_service
            .create_verification_email(&user, email_verification_expiry)
            .await?;
        let link = format!(
            "{}/email/verify?token={}",
            &configuration.api_url, &verification_token
        );

        return match configuration.auth.strategy {
            AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
                session.insert(support::SESSION_COOKIE, token)?;
                Ok(HttpResponse::Created()
                    .json(AuthResponse::new(user).with_verification(&link, &verification_token)))
            })?,
            AuthStrategy::Jwt => {
                auth_service
                    .issue_jwt(&user, &configuration)
                    .await
                    .map(|tokens| {
                        Ok(HttpResponse::Created().json(
                            AuthResponse::new(user)
                                .with_jwt(tokens, configuration.auth.jwt.expires_in)
                                .with_verification(&link, &verification_token),
                        ))
                    })?
            }
        };
    }

    match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
            session.insert(support::SESSION_COOKIE, token)?;
            Ok(HttpResponse::Created().json(AuthResponse::new(user)))
        })?,
        AuthStrategy::Jwt => auth_service
            .issue_jwt(&user, &configuration)
            .await
            .map(|tokens| {
                Ok(HttpResponse::Created().json(
                    AuthResponse::new(user).with_jwt(tokens, configuration.auth.jwt.expires_in),
                ))
            })?,
    }
}

#[utoipa::path(
        get,
        path = "/auth/session",
        tag = "Auth",
        summary = "Get current session",
        description = "Returns the currently authenticated user's session data. Requires a valid Bearer token.",
        security(
            ("session_auth" = []),  // OR
            ("bearer_auth"    = []),
        ),
        responses(
            (status = 200, description = "Session data returned", body = Session),
            (status = UNAUTHORIZED, description = "Unauthorized — missing or invalid token", body = ErrorResponse),
            (status = 403, description = "Account suspended or unverified", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(name = "Get user session", skip(session))]
pub async fn get_session(session: Session) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(session))
}

#[utoipa::path(
        post,
        path = "/auth/refresh-token",
        tag = "Auth",
        summary = "Refresh access token",
        description = "Issues a new access token using a valid refresh token. Rotate refresh tokens on each call.",
        security(
            ("session_auth" = []),  // OR
            ("bearer_auth"    = []),
        ),
        responses(
            (status = 200, description = "New token issued", body = AuthResponse),
            (status = 401, description = "Refresh token invalid or expired", body = ErrorResponse),
            (status = BAD_REQUEST, description = "invalid request", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(
    name = "Refresh user accessToken",
    skip(req, auth_service, configuration)
)]
pub async fn refresh_token(
    req: web::Json<RefreshTokenRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
) -> Result<HttpResponse> {
    tracing::info!("user is refreshing token");

    let user_id = auth_service
        .consume_refresh_token(&req.0.refresh_token, &configuration.security.secret_key)
        .await?;

    let user: User = auth_service.find_user(&user_id).await?;

    auth_service
        .issue_jwt(&user, &configuration)
        .await
        .map(|tokens| {
            Ok(HttpResponse::Ok()
                .json(AuthResponse::new(user).with_jwt(tokens, configuration.auth.jwt.expires_in)))
        })?
}

#[utoipa::path(
        post,
        path = "/auth/logout",
        tag = "Auth",
        summary = "Logout",
        description = "Invalidates the current session and refresh token. The client should discard stored tokens.",
        security(
            ("session_auth" = []),  // OR
            ("bearer_auth"    = []),
        ),
        responses(
            (status = 200, description = "Logged out successfully"),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = BAD_REQUEST, description = "invalid request", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(
    name = "Logout user",
    skip(req, auth_service, session, session_manager)
)]
async fn logout(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    req: web::Json<RefreshTokenRequest>,
    session: Session,
    session_manager: actix_session::Session,
) -> Result<HttpResponse> {
    let result = match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.invalidate_session(&session.token).await,
        AuthStrategy::Jwt => {
            auth_service
                .invalidate_jwt(&req.0.refresh_token, &configuration.security.secret_key)
                .await
        }
    };

    session_manager.purge();
    result.map(|_| Ok(HttpResponse::Ok().finish()))?
}

#[utoipa::path(
        post,
        path = "/auth/password/forgot",
        tag = "Auth",
        summary = "Request a password reset",
        description = "Sends a password reset link to the provided email address if an account exists.",
        request_body(description = "Email address to send the reset link to", content = EmailRequest),
        responses(
            (status = 200, description = "Reset email sent if account exists", body = ResetLink),
            (status = BAD_REQUEST, description = "invalid request", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(name = "Forgot password", skip(auth_service, configuration))]
async fn request_password_reset(
    req: web::Json<EmailRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
) -> Result<HttpResponse> {
    req.validate()
        .map_err(|err| Error::BadRequest(err.to_string()))?;

    let start = std::time::Instant::now();

    let email: String = req.into_inner().email;
    // 2.
    let mut bucket = RATE_LIMITS.entry(email.clone()).or_default();
    bucket.run()?;

    let result = async {
        let user = auth_service.find_user_by_email(&email).await?;
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        // 3.
        auth_service.revoke_password_reset_token(user_id).await?;

        // 4.
        let token = Token::with_size64().generate();
        let hashed_token = Token::hash(&token);

        // 5.
        let expiry_timestamp = chrono::Utc::now()
            + chrono::Duration::seconds(configuration.auth.password.reset.token_expires_in);

        let password_reset_token = PasswordResetToken::default()
            .with_user_id(user_id)
            .with_token_hash(&hashed_token)
            .with_expiray(&expiry_timestamp);
        auth_service
            .insert_password_reset_token(password_reset_token)
            .await?;

        // 6.
        let mut bucket = RATE_LIMITS.entry(user_id.clone()).or_default();
        bucket.run()?;

        let link = format!(
            "{}/auth/password/reset?token={}",
            &configuration.api_url, &token
        );
        let reset_link = ResetLink {
            link,
            expires_at: expiry_timestamp,
        };
        Ok::<ResetLink, Error>(reset_link)
    }
    .await;

    support::throttle_since(start).await;

    // NOTE Use HMAC or JWT signing so you can later verify it server-side.
    // NOTE maybe use for email_verification
    match result {
        Ok(reset_link) => Ok(HttpResponse::Ok().json(reset_link)),
        Err(err) => {
            tracing::error!("Password reset failed for email {}: {}", email, err);
            Err(err)
        }
    }
}

#[utoipa::path(
        get,
        path = "/auth/password/reset",
        tag = "Auth",
        summary = "Render password reset form",
        description = "Validates the reset token from the email link and renders the password reset form.",
        params(
            ("token" = TokenQuery, Query, description = "Password reset token")
        ),
        responses(
            (status = 200, description = "Reset form rendered", content_type = "text/html", body = String),
            (status = BAD_REQUEST, description = "invalid request", body = ErrorResponse),
        ),
    )]
async fn render_reset_form(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    let token: &str = &query.token;
    auth_service.validate_reset_password_token(token).await?;

    let csrf_token = Token::with_size64().generate();
    session.clear();
    session.insert(support::CSRF_COOKIE, &csrf_token)?;

    let body = include_str!("templates/update_password.html")
        .replace("{{TOKEN}}", token)
        .replace("{{CSRF_TOKEN}}", &csrf_token);
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

#[utoipa::path(
        post,
        path = "/auth/password/reset",
        tag = "Auth",
        summary = "Submit new password",
        description = "Submits a new password using a valid reset token. Invalidates the token after use.",
        request_body(description = "Reset token and the new password", content = ResetPasswordRequest),
        responses(
            (
                status = 302,
                description = "Redirect to success page", 
                headers(
                    ("Location" = String, description = "Redirect URL")
                )
            ),
            (status = BAD_REQUEST, description = "invalid request", body = ErrorResponse),
        ),
)]
async fn submit_new_password(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    session: actix_session::Session,
    form: web::Form<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    // 0. validat password strength
    form.validate_with_args(&configuration.auth.password.requirements)
        .map_err(|err| Error::BadRequest(err.to_string()))?;

    // 0.5 Verify CSRF token
    if let Some(expected) = session.get::<String>(support::CSRF_COOKIE)? {
        if !Token::verify(&expected, &form.csrf_token) {
            return Ok(HttpResponse::Forbidden().body("Invalid CSRF token"));
        }
    } else {
        return Ok(HttpResponse::Forbidden().body("Missing CSRF token"));
    }
    session.remove("csrf_token");

    let token: &str = &form.token;

    // 1. ReValidate token
    let reset_token = auth_service.validate_reset_password_token(token).await?;
    let reset_token_id = reset_token.id.as_ref().ok_or(Error::MalformedData {
        field: CredentialField::ObjectId,
    })?;
    let user_id = reset_token.user_id;

    // NOTE → Rate limit per token

    // 2. Ensure password is different then previous
    let account = auth_service.find_account(&user_id).await?;
    if account.locked {
        return Err(Error::AccountSuspended {});
    }
    if Password::verify(&form.password, &account.password) {
        tracing::warn!("Password reuse attempt for user: {}", user_id);
        return Err(Error::InvalidCredentials {
            field: CredentialField::Password,
            reason: FailureReason::AlreadyExist,
        });
    }

    // 3.
    let hashed_password = Password::hash(&form.password)?;
    auth_service
        .update_user_password(&user_id, &hashed_password)
        .await?;
    tracing::info!("Password successfully reset for user: {}", user_id);

    // 4.
    auth_service
        .invalidate_password_reset_token(reset_token_id)
        .await?;

    // 6. TODO it may not be neccessary
    auth_service.logout_all(&user_id).await?;

    let success_redirect = match configuration.auth.password.reset.success_redirect {
        Some(url) => url,
        None => configuration.api_url,
    };
    Ok(HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, success_redirect))
        .finish())
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/password/forgot", web::post().to(request_password_reset))
        .route("/password/reset", web::get().to(render_reset_form))
        .route("/password/reset", web::post().to(submit_new_password))
        .route("/refresh-token", web::post().to(refresh_token))
        .service(
            web::scope("")
                .wrap(from_fn(authorization_middleware))
                .wrap(from_fn(auth_middleware))
                .route("/session", web::get().to(get_session))
                .route("/logout", web::post().to(logout)),
        )
}
