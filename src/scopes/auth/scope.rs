use actix_web::{
    HttpResponse, Scope,
    web::{self, Data},
};
use serde_json::json;

use crate::{
    error::FailureReason,
    extractors::ConfigurationExtractor,
    scopes::{
        auth::{
            models::AuthResponse,
            service::{PasswordResetTokenServiceTrait, SessionServiceTrait},
        },
        config::AuthStrategy,
    },
    services::{email::sender::Email, jwt::Tokens, session::model::Session},
    utils::{AuthenticationHasher, Utils},
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
use crate::{middlewares::rate_limit::RateLimiter, scopes::auth::service::JwtServiceTrait};

use super::models::{EmailRequest, LoginRequest, TokenQuery};
use super::reset_password::model::PasswordResetToken;
use super::user::User;

// TODO NOTE FIXME HACK
// user docker envs to pass app config
// Don't use http post to send configuration from client
// create a config.yaml then pass it to docker
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

    let user_id = user.id.as_slice().concat();
    auth_service
        .validate_jwt(payload, user_id.to_string())
        .await?;

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
    match configuration.auth.strategy {
        AuthStrategy::Session => auth_service
            .invalidate_session(session.token)
            .await
            .map(|_| Ok(HttpResponse::Ok().json(json!({ "status": "ok" }))))?,
        AuthStrategy::Jwt => auth_service
            .invalidate_jwt(payload.jti)
            .await
            .map(|_| Ok(HttpResponse::Ok().json(json!({ "status": "ok" }))))?,
    }
}

#[tracing::instrument(name = "Forgot password", skip(auth_service, rate_limiter))]
async fn forgot_password(
    ValidatedPayload(req): ValidatedPayload<EmailRequest>,
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    rate_limiter: Data<RateLimiter>,
) -> Result<HttpResponse> {
    // 1. Extract email from payload
    let email: String = req.email;

    /*
     * [ DON'T SEND A NON EXISTENCE EMAIL ERROR MESSAGE ]
     */
    // 2. Check if email exists
    if let Ok(user) = auth_service.find_user_by_email(&email).await {
        let user_id = user.id.as_slice().concat();

        // Check rate limiting
        rate_limiter.check_rate_limit(&user)?;

        // 3. If exists: invalidate existing tokens
        auth_service
            .revoke_password_reset_token(user_id.to_string())
            .await?;

        // 4. Generate a new token + hash
        // try to use something like: Utils::generate_token(32).hash()
        let token = Utils::generate_token(32);
        let hashed_token = Utils::hash_token(&token);

        // 5. If exists: store token record
        let otp = PasswordResetToken::default()
            .with_user_id(user_id)
            .with_token_hash(hashed_token);
        auth_service.insert_password_reset_token(otp).await?;

        // 6. If exists: send email: exp-> api/reset-password?token=xxxxxxx
        let to = "hakoudev@gmail.com";
        let body = format!(
            include_str!("../../services/email/templates/password_reset.html"),
            &user.username, &token, &token
        );
        Email::default().to(to).send(&body).await?;

        // 7. [FIXME] function name is not good
        // Increment user's reset attempt count
        // Limit reset password requests
        auth_service.process_reset_request(user).await?;
    }

    Ok(HttpResponse::Ok().json("if email exists a link will be sent"))
}

async fn reset_password(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
) -> Result<HttpResponse> {
    let token: &str = &query.token;
    auth_service.validate_reset_password_token(token).await?;

    Ok(HttpResponse::Ok().json("Password reset initiated"))
}

async fn update_password(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ValidatedQuery(request): ValidatedQuery<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    // 1. ReValidate token
    let token: &str = &request.token;
    let reset_token = auth_service.validate_reset_password_token(token).await?;

    // 2. Ensure password is different then previous
    let user_id = reset_token.user_id;
    let user = auth_service.find_user(user_id.to_string()).await?;
    if user.account_locked {
        return Err(Error::AccountSuspended { user_id });
    }
    if Utils::verify_password(&request.password, &user.password) {
        tracing::warn!(
            "Current password is similair to previous password, user: {}",
            user_id
        );
        return Err(Error::InvalidCredentials {
            field: CredentialField::Password,
            reason: FailureReason::HashMismatch,
        });
    }

    // 3. Hash new password using argon2
    let hashed_password = Utils::hash_password(&request.password)?;
    auth_service
        .update_user_password(user_id.to_string(), hashed_password)
        .await?;

    // 4. Invalidate PasswordResetToken, Mark it as used (used_at = now)
    auth_service
        .invalidate_password_reset_token(reset_token.id.unwrap_or_default().to_string())
        .await?;

    // 5. [TODO] invalidate passwordTokens related to user [THIS MAY NOT BE NEEDED]
    auth_service
        .revoke_password_reset_token(user_id.to_string())
        .await?;

    // 6. Update user.last_password_reset to now(), reset passwordResetCount->0
    auth_service
        .reset_password_state(user_id.to_string())
        .await?;

    // 7. TODO it may not be neccessary
    auth_service
        .logout_all(user_id.to_string())
        .await
        .map(|user| Ok(HttpResponse::Ok().json(user)))?
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/session", web::get().to(get_session))
        .route("/refreshToken", web::post().to(refresh_token))
        .route("/logout", web::post().to(logout))
        .route("/forgot-password", web::post().to(forgot_password))
        .route("/reset-password", web::get().to(reset_password))
        .route("/update-password", web::put().to(update_password))
}
