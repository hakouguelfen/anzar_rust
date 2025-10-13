use actix_web::{
    HttpResponse, Scope,
    web::{self},
};
use serde_json::json;

use crate::{
    error::FailureReason,
    extractors::ConfigurationExtractor,
    middlewares::rate_limiting::RATE_LIMITS,
    scopes::{
        auth::{
            models::AuthResponse,
            service::{PasswordResetTokenServiceTrait, SessionServiceTrait},
        },
        config::AuthStrategy,
    },
    services::{email::sender::Email, jwt::Tokens, session::model::Session},
    utils::{CustomPasswordHasher, Password, TokenHasher},
};
use crate::{
    error::{CredentialField, Error, Result},
    extractors::AuthServiceExtractor,
    scopes::auth::models::ResetPasswordRequest,
};
use crate::{
    extractors::{AuthPayload, AuthenticatedUser, ValidatedPayload, ValidatedQuery},
    scopes::auth::service::UserServiceTrait,
};
use crate::{scopes::auth::service::JwtServiceTrait, utils::Token};

use super::models::{EmailRequest, LoginRequest, TokenQuery};
use super::reset_password::model::PasswordResetToken;
use super::user::User;

#[tracing::instrument(
    name = "Login user",
    skip(req, auth_service, session),
    fields(user_email = %req.email)
)]
async fn login(
    ValidatedPayload(req): ValidatedPayload<LoginRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    let user: User = auth_service
        .authenticate_user(&req.email, &req.password)
        .await?;

    match configuration.auth.strategy {
        AuthStrategy::Session => auth_service.issue_session(&user).await.map(|token| {
            session.insert("SessionID", token)?;
            Ok(HttpResponse::Ok().json(AuthResponse::with_jwt(Tokens::default(), user.into())))
        })?,
        AuthStrategy::Jwt => auth_service
            .issue_and_save_tokens(&user)
            .await
            .map(|tokens| {
                Ok(HttpResponse::Ok().json(AuthResponse::with_jwt(tokens, user.into())))
            })?,
    }
}

#[tracing::instrument(
    name = "Register user",
    skip(req, auth_service, session),
    fields(user_email = %req.email, user_name = %req.username)
)]
async fn register(
    ValidatedPayload(req): ValidatedPayload<User>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    session: actix_session::Session,
) -> Result<HttpResponse> {
    let user: User = auth_service.create_user(req).await?;

    match configuration.auth.strategy {
        AuthStrategy::Session => {
            auth_service.issue_session(&user).await.map(|token| {
                session.insert("SessionID", token)?;
                Ok(HttpResponse::Created()
                    .json(AuthResponse::with_jwt(Tokens::default(), user.into())))
            })?
        }
        AuthStrategy::Jwt => auth_service
            .issue_and_save_tokens(&user)
            .await
            .map(|tokens| {
                Ok(HttpResponse::Created().json(AuthResponse::with_jwt(tokens, user.into())))
            })?,
    }
}

#[tracing::instrument(name = "Get user session", skip(session))]
async fn get_session(session: Session) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(session))
}

#[tracing::instrument(
    name = "Regenerate user accessToken",
    skip(payload, auth_service, authenticated_user),
    fields(user_id = %payload.user_id)
)]
async fn refresh_token(
    payload: AuthPayload,
    authenticated_user: AuthenticatedUser,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
) -> Result<HttpResponse> {
    let user: User = authenticated_user.0;

    let user_id = user.id.as_ref().ok_or(Error::MalformedData {
        field: CredentialField::ObjectId,
    })?;
    auth_service.validate_jwt(payload, user_id).await?;

    auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(AuthResponse::with_jwt(tokens, user.into()))))?
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

#[tracing::instrument(name = "Forgot password", skip(auth_service))]
async fn request_password_reset(
    ValidatedPayload(req): ValidatedPayload<EmailRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
) -> Result<HttpResponse> {
    const TIMING_DELAY_MS: u64 = 800;
    const RESPONSE_MESSAGE: &str =
        "If an account exists with this email, a password reset link will be sent";
    let start = std::time::Instant::now();

    let email: String = req.email;
    let result = async {
        let user = auth_service.find_user_by_email(&email).await?;
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        // 2.
        let mut bucket = RATE_LIMITS.entry(user_id.clone()).or_default();
        bucket.run()?;

        // 3.
        auth_service.revoke_password_reset_token(user_id).await?;

        // 4.
        let token = Token::generate(64);
        let hashed_token = Token::hash(&token);

        // 5.
        let otp = PasswordResetToken::default()
            .with_user_id(user_id)
            .with_token_hash(&hashed_token);
        auth_service.insert_password_reset_token(otp).await?;

        // 6.
        Email::default()
            .to(&email)
            // .to("hakoudev@gmail.com")
            .send(&user.username, &token)
            .await?;
        tracing::info!("Password reset requested for email: {}", email);

        auth_service.increment_reset_attempts(user).await?;
        Ok::<(), Error>(())
    }
    .await;

    if let Err(e) = result {
        tracing::error!("Password reset failed for email {}: {}", email, e);
    }

    let elapsed = start.elapsed().as_millis() as u64;
    if elapsed < TIMING_DELAY_MS {
        std::thread::sleep(std::time::Duration::from_millis(TIMING_DELAY_MS - elapsed));
    }

    Ok(HttpResponse::Ok().json(json!({ "message": RESPONSE_MESSAGE })))
}

async fn render_reset_form(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
) -> Result<HttpResponse> {
    let token: &str = &query.token;
    auth_service.validate_reset_password_token(token).await?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("templates/update_password.html")))
}

// NOTE FIXME TODO: CSRF protection
async fn submit_new_password(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    request: web::Form<ResetPasswordRequest>,
    // ValidatedQuery(request): ValidatedQuery<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    const RESPONSE_MESSAGE: &str =
        "Password successfully reset. Please login with your new password.";

    // 1. ReValidate token
    let token: &str = &request.token;
    let reset_token = auth_service.validate_reset_password_token(token).await?;

    let user_id = reset_token.user_id;
    let reset_token_id = reset_token.id.ok_or(Error::InvalidToken {
        token_type: crate::error::TokenErrorType::PasswordResetToken,
        reason: crate::error::InvalidTokenReason::Malformed,
    })?;

    // 2. Ensure password is different then previous
    let user = auth_service.find_user(&user_id).await?;
    if user.account_locked {
        return Err(Error::AccountSuspended { user_id });
    }
    if Password::verify(&request.password, &user.password) {
        tracing::warn!("Password reuse attempt for user: {}", user_id);
        return Err(Error::InvalidCredentials {
            field: CredentialField::Password,
            reason: FailureReason::AlreadyExist,
        });
    }

    // 3.
    let hashed_password = Password::hash(&request.password)?;
    auth_service
        .update_user_password(&user_id, &hashed_password)
        .await?;
    tracing::info!("Password successfully reset for user: {}", user_id);

    // 4.
    auth_service
        .invalidate_password_reset_token(&reset_token_id)
        .await?;

    // 6.
    auth_service.reset_password_state(&user_id).await?;

    // 7. TODO it may not be neccessary
    auth_service.logout_all(&user_id).await?;

    // 8. Send security notification email
    // Email::default()
    //     .to("hakoudev@gmail.com")
    //     .send(&user.username, &token)
    //     .await
    //     .ok();

    Ok(HttpResponse::Ok().json(json!({ "message": RESPONSE_MESSAGE })))
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/session", web::get().to(get_session))
        .route("/refreshToken", web::post().to(refresh_token))
        .route("/logout", web::post().to(logout))
        .route("/password/forgot", web::post().to(request_password_reset))
        .route("/password/reset", web::get().to(render_reset_form))
        .route("/password/reset", web::post().to(submit_new_password))
}
