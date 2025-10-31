use actix_web::{
    HttpResponse, Scope,
    middleware::from_fn,
    web::{self},
};
use serde_json::json;
use validator::ValidateArgs;

use crate::{
    config::AuthStrategy,
    error::{CredentialField, Error, FailureReason, Result},
    utils::DeviceCookie,
};
use crate::{
    extractors::{
        AuthPayload, AuthServiceExtractor, AuthenticatedUser, ConfigurationExtractor,
        ValidatedPayload, ValidatedQuery,
    },
    scopes::auth::models::RegisterRequest,
};
use crate::{
    middlewares::{
        account_validation::account_validation_middleware, rate_limiting::RATE_LIMITS,
        token_validation::token_validation_middleware,
    },
    scopes::auth::models::ResetLink,
};

use crate::utils::Token;
use crate::{
    services::{
        jwt::service::JwtServiceTrait,
        session::{model::Session, service::SessionServiceTrait},
    },
    utils::{CustomPasswordHasher, Password, TokenHasher},
};

use crate::scopes::{
    auth::{
        models::{AuthResponse, ResetPasswordRequest},
        reset_password::service::PasswordResetTokenServiceTrait,
    },
    user::service::UserServiceTrait,
};

use super::models::{EmailRequest, LoginRequest, TokenQuery};
use super::reset_password::model::PasswordResetToken;
use super::user::User;

use super::support;

#[tracing::instrument(
    name = "Login user",
    skip(req, auth_service, configuration, session),
    fields(user_email = %req.email)
)]
async fn login(
    req: web::Json<LoginRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    req.validate_with_args(&configuration.auth.password.requirements)
        .map_err(|err| Error::BadRequest(err.to_string()))?;

    let mut device_cookie = DeviceCookie::new(&configuration.security.secret_key);
    let key = support::construct_key_from_device_cookie(&session, &device_cookie, &req.email)?;

    // unified lockout check
    if auth_service.user_service.exists(&key) {
        return Err(Error::AccountSuspended { user_id: "".into() });
    }

    match auth_service
        .authenticate_user(&req.email, &req.password)
        .await?
    {
        true => {
            let cookie = device_cookie.issue(&req.email);
            session.insert("DeviceCookie", &cookie)?;

            Ok(())
        }
        false => {
            let pass_config = configuration.auth.password;
            tracing::error!("Failed to verify password");

            let device_cookie = session.get::<String>("DeviceCookie")?;
            let attempts = auth_service
                .register_failed_attempt(&req.email, device_cookie.as_deref(), &pass_config)
                .await?;

            // Progressive delay
            support::delay(attempts as u32).await;

            Err(Error::InvalidCredentials {
                field: CredentialField::Password,
                reason: FailureReason::HashMismatch,
            })
        }
    }?;

    let email_verification = configuration.auth.email.verification;

    let user = auth_service.find_user_by_email(&req.email).await?;
    if email_verification.required && !user.verified {
        return Err(Error::AccuontNotVerified {
            field: CredentialField::Email,
        });
    }

    let secret_key = configuration.security.secret_key.as_bytes();
    let jwt_config = configuration.auth.jwt;
    match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
            session.insert("SessionID", token)?;
            Ok(HttpResponse::Ok().json(AuthResponse::new(user.into())))
        })?,
        AuthStrategy::Jwt => auth_service
            .issue_jwt(&user, secret_key, jwt_config)
            .await
            .map(|tokens| {
                Ok(HttpResponse::Ok().json(AuthResponse::new(user.into()).with_jwt(tokens)))
            })?,
    }
}

#[tracing::instrument(
    name = "Register user",
    skip(req, auth_service, configuration, session),
    fields(user_email = %req.email, user_name = %req.username)
)]
async fn register(
    req: web::Json<RegisterRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    req.validate_with_args(&configuration.auth.password.requirements)
        .map_err(|err| Error::BadRequest(err.to_string()))?;

    let user = auth_service.create_user(req.into_inner()).await?;

    let secret_key = configuration.security.secret_key.as_bytes();
    let jwt_config = configuration.auth.jwt;

    let email_config = configuration.auth.email;
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
                session.insert("SessionID", token)?;
                Ok(HttpResponse::Created().json(
                    AuthResponse::new(user.into()).with_verification(&link, &verification_token),
                ))
            })?,
            AuthStrategy::Jwt => auth_service
                .issue_jwt(&user, secret_key, jwt_config)
                .await
                .map(|tokens| {
                    Ok(HttpResponse::Created().json(
                        AuthResponse::new(user.into())
                            .with_jwt(tokens)
                            .with_verification(&link, &verification_token),
                    ))
                })?,
        };
    }

    match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
            session.insert("SessionID", token)?;
            Ok(HttpResponse::Created().json(AuthResponse::new(user.into())))
        })?,
        AuthStrategy::Jwt => auth_service
            .issue_jwt(&user, secret_key, jwt_config)
            .await
            .map(|tokens| {
                Ok(HttpResponse::Created().json(AuthResponse::new(user.into()).with_jwt(tokens)))
            })?,
    }
}

#[tracing::instrument(name = "Get user session", skip(session))]
async fn get_session(session: Session) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(session))
}

#[tracing::instrument(
    name = "Regenerate user accessToken",
    skip(payload, auth_service,configuration, authenticated_user),
    fields(user_id = %payload.user_id)
)]

async fn refresh_token(
    payload: AuthPayload,
    authenticated_user: AuthenticatedUser,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
) -> Result<HttpResponse> {
    let user: User = authenticated_user.0;

    let user_id = user.id.as_ref().ok_or(Error::MalformedData {
        field: CredentialField::ObjectId,
    })?;
    auth_service.consume_refresh_token(payload, user_id).await?;

    let secret_key = configuration.security.secret_key.as_bytes();
    let jwt_config = configuration.auth.jwt;
    auth_service
        .issue_jwt(&user, secret_key, jwt_config)
        .await
        .map(
            |tokens| Ok(HttpResponse::Ok().json(AuthResponse::new(user.into()).with_jwt(tokens))),
        )?
}

#[tracing::instrument(
    name = "Logout user",
    skip(payload, auth_service, session),
    fields(user_id = %payload.user_id)
)]
async fn logout(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    payload: AuthPayload,
    session: Session,
) -> Result<HttpResponse> {
    let result = match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.invalidate_session(&session.token).await,
        AuthStrategy::Jwt => auth_service.invalidate_jwt(&payload.jti).await,
    };
    result.map(|_| Ok(HttpResponse::Ok().json(json!({ "status": "ok" }))))?
}

#[tracing::instrument(name = "Forgot password", skip(auth_service, configuration))]
async fn request_password_reset(
    ValidatedPayload(req): ValidatedPayload<EmailRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
) -> Result<HttpResponse> {
    const TIMING_DELAY_MS: u64 = 800;
    let start = std::time::Instant::now();

    let email: String = req.email;
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
        let token = Token::generate(64);
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
        auth_service.increment_reset_attempts(user).await?;

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

    let elapsed = start.elapsed().as_millis() as u64;
    if elapsed < TIMING_DELAY_MS {
        tokio::time::sleep(tokio::time::Duration::from_millis(
            TIMING_DELAY_MS.saturating_sub(elapsed),
        ))
        .await;
    }

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

async fn render_reset_form(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    let token: &str = &query.token;
    auth_service.validate_reset_password_token(token).await?;

    let csrf_token = Token::generate(64);
    session.insert("csrf_token", &csrf_token)?;

    let body = include_str!("templates/update_password.html")
        .replace("{{TOKEN}}", token)
        .replace("{{CSRF_TOKEN}}", &csrf_token);
    Ok(HttpResponse::Ok()
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .content_type("text/html; charset=utf-8")
        .body(body))
}

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
    if let Some(expected) = session.get::<String>("csrf_token")? {
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

    // NOTE: → Rate limit per token

    // 2. Ensure password is different then previous
    let user = auth_service.find_user(&user_id).await?;
    if user.account_locked {
        return Err(Error::AccountSuspended { user_id });
    }
    if Password::verify(&form.password, &user.password) {
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

    // 6.
    auth_service.reset_password_state(&user_id).await?;

    // 7. TODO it may not be neccessary
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
        .service(
            web::scope("")
                .wrap(from_fn(account_validation_middleware))
                .wrap(from_fn(token_validation_middleware))
                .route("/session", web::get().to(get_session))
                .route("/refreshToken", web::post().to(refresh_token))
                .route("/logout", web::post().to(logout)),
        )
}
