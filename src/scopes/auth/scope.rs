use actix_web::{
    HttpResponse, Scope,
    web::{self, Data},
};
use serde_json::json;

use crate::scopes::auth::{Error, models::ResetPasswordRequest};
use crate::scopes::auth::{models::AuthResponse, service::PasswordResetTokenServiceTrait};
use crate::{
    core::extractors::{
        AuthPayload, AuthenticatedUser, ServiceManagerExtractor, ValidatedPayload, ValidatedQuery,
    },
    scopes::auth::service::UserServiceTrait,
};
use crate::{core::rate_limiter::RateLimiter, scopes::auth::service::JwtServiceTrait};

use super::error::Result;
use super::reset_password::model::PasswordResetTokens;
use super::user::User;
use super::{
    email::manager::Email,
    models::{EmailRequest, LoginRequest, TokenQuery},
    utils::{AuthenticationHasher, Utils},
};

#[tracing::instrument(
    name = "Login user",
    skip(req, repo),
    fields(user_email = %req.email)
)]
async fn login(
    ValidatedPayload(req): ValidatedPayload<LoginRequest>,
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
) -> Result<HttpResponse> {
    let user: User = repo
        .auth_service
        .authenticate_user(&req.email, &req.password)
        .await?;

    repo.auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(AuthResponse::from(tokens, user.into()))))?
}

#[tracing::instrument(
    name = "Register user",
    skip(req, repo),
    fields(user_email = %req.email, user_name = %req.username)
)]
async fn register(
    ValidatedPayload(req): ValidatedPayload<User>,
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
) -> Result<HttpResponse> {
    let user: User = repo.auth_service.create_user(req).await?;

    repo.auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::Created().json(AuthResponse::from(tokens, user.into()))))?
}

#[tracing::instrument(
    name = "Regenerate user accessToken",
    skip(payload, repo, authenticated_user),
    fields(user_id = %payload.user_id)
)]
async fn refresh_token(
    payload: AuthPayload,
    authenticated_user: AuthenticatedUser,
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
) -> Result<HttpResponse> {
    let user_id = authenticated_user.0.id.unwrap_or_default();
    repo.auth_service.validate_jwt(payload, user_id).await?;

    repo.auth_service
        .issue_and_save_tokens(&authenticated_user.0)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(tokens)))?
}

#[tracing::instrument(
    name = "Logout user",
    skip(payload, repo),
    fields(user_id = %payload.user_id)
)]
async fn logout(
    payload: AuthPayload,
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
) -> Result<HttpResponse> {
    repo.auth_service
        .logout(payload)
        .await
        .map(|_| Ok(HttpResponse::Ok().json(json!({ "status": "ok" }))))?
}

#[tracing::instrument(name = "Forgot password", skip(repo, rate_limiter))]
async fn forgot_password(
    ValidatedPayload(req): ValidatedPayload<EmailRequest>,
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
    rate_limiter: Data<RateLimiter>,
) -> Result<HttpResponse> {
    // 1. Extract email from payload
    let email: String = req.email;

    /*
     * [ DON'T SEND A NON EXISTENCE EMAIL ERROR MESSAGE ]
     */
    // 2. Check if email exists
    if let Ok(user) = repo.auth_service.find_user_by_email(&email).await {
        let user_id = user.id.unwrap_or_default();

        // Check rate limiting
        rate_limiter.check_rate_limit(&user)?;

        // 3. If exists: invalidate existing tokens
        repo.auth_service
            .revoke_password_reset_token(user_id)
            .await?;

        // 4. Generate a new token + hash
        // try to use something like: Utils::generate_token(32).hash()
        let token = Utils::generate_token(32);
        let hashed_token = Utils::hash_token(&token);

        // 5. If exists: store token record
        let otp = PasswordResetTokens::default()
            .with_user_id(user_id)
            .with_token_hash(hashed_token);
        repo.auth_service.insert_password_reset_token(otp).await?;

        // 6. If exists: send email: exp-> api/reset-password?token=xxxxxxx
        let to = "hakoudev@gmail.com";
        let body = format!(
            include_str!("email/templates/password_reset.html"),
            &user.username, &token, &token
        );
        Email::default().to(to).send(&body).await?;

        // 7. Increment user's reset attempt count
        //    Limit reset password requests
        repo.auth_service.process_reset_request(user).await?;
    }

    Ok(HttpResponse::Ok().json("if email exists a link will be sent"))
}

async fn reset_password(
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
) -> Result<HttpResponse> {
    let token: &str = &query.token;
    repo.auth_service
        .validate_reset_password_token(token)
        .await?;

    Ok(HttpResponse::Ok().json("Password reset initiated"))
}

async fn update_password(
    ServiceManagerExtractor(repo): ServiceManagerExtractor,
    ValidatedQuery(request): ValidatedQuery<ResetPasswordRequest>,
) -> Result<HttpResponse> {
    // 1. ReValidate token
    let token: &str = &request.token;
    let reset_token = repo
        .auth_service
        .validate_reset_password_token(token)
        .await?;

    // 2. Ensure password is different then previous
    let user_id = reset_token.user_id;
    let user = repo.auth_service.find_user(user_id).await?;
    if user.account_locked {
        return Err(Error::AccountSuspended);
    }
    if Utils::verify_password(&request.password, &user.password) {
        tracing::warn!(
            "Current password is similair to previous password, user: {}",
            user_id
        );
        return Err(Error::InvalidCredentials);
    }

    // 3. Hash new password using argon2
    let hashed_password = Utils::hash_password(&request.password)?;
    repo.auth_service
        .update_user_password(user_id, hashed_password)
        .await?;

    // 4. Invalidate PasswordResetToken, Mark it as used (used_at = now)
    repo.auth_service
        .invalidate_password_reset_token(reset_token.id.unwrap_or_default())
        .await?;

    // 5. [TODO] invalidate passwordTokens related to user [THIS MAY NOT BE NEEDED]
    repo.auth_service
        .revoke_password_reset_token(user_id)
        .await?;

    // 6. Update user.last_password_reset to now(), reset passwordResetCount->0
    repo.auth_service.reset_password_state(user_id).await?;

    // 7. TODO it may not be neccessary
    repo.auth_service
        .logout_all(user_id)
        .await
        .map(|user| Ok(HttpResponse::Ok().json(user)))?
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/refreshToken", web::post().to(refresh_token))
        .route("/logout", web::post().to(logout))
        .route("/forgot-password", web::post().to(forgot_password))
        .route("/reset-password", web::get().to(reset_password))
        .route("/update-password", web::put().to(update_password))
}
