use actix_web::{
    HttpResponse, Scope,
    web::{self, Data, Json, Query},
};
use chrono::Utc;
use mongodb::bson::oid::ObjectId;

use crate::{
    core::{rate_limiter::RateLimiter, repository::repository_manager::ServiceManager},
    scopes::auth::Error,
};

use super::extenstion::AuthResponseTrait;
use super::user::User;
use super::{Claims, reset_password::model::PasswordResetTokens};
use super::{
    email::manager::Email,
    models::{EmailRequest, LoginRequest, TokenQuery},
    utils::{AuthenticationHasher, Utils},
};
use super::{error::Result, models::AuthPayload};

#[tracing::instrument(
    name = "Login user",
    skip(req, repo),
    fields(user_email = %req.email)
)]
async fn login(req: Json<LoginRequest>, repo: Data<ServiceManager>) -> Result<HttpResponse> {
    let user: User = repo
        .auth_service
        .check_credentials(req.into_inner())
        .await?;

    repo.auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::set_auth_headers(tokens, user.as_response())))?
}

#[tracing::instrument(
    name = "Register user",
    skip(req, repo),
    fields(user_email = %req.email, user_name = %req.username)
)]
async fn register(req: Json<User>, repo: Data<ServiceManager>) -> Result<HttpResponse> {
    let user: User = repo.auth_service.create_user(req.into_inner()).await?;

    repo.auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::set_auth_headers(tokens, user.as_response())))?
}

#[tracing::instrument(
    name = "Regenerate user accessToken",
    skip(payload, repo),
    fields(user_id = %payload.user_id)
)]
async fn refresh_token(payload: AuthPayload, repo: Data<ServiceManager>) -> Result<HttpResponse> {
    // NOTE: maybe save valid tokens to user doc
    let user: User = repo.auth_service.validate_token(payload).await?;

    repo.auth_service
        .issue_and_save_tokens(&user)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(tokens)))?
}

#[tracing::instrument(
    name = "Logout user",
    skip(claims, repo),
    fields(user_id = %claims.sub)
)]
async fn logout(claims: Claims, repo: Data<ServiceManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();
    repo.auth_service
        .logout(user_id)
        .await
        .map(|user| Ok(HttpResponse::Ok().json(user)))?
}

#[tracing::instrument(name = "Forgot password", skip(repo, rate_limiter))]
async fn forgot_password(
    req: Json<EmailRequest>,
    repo: Data<ServiceManager>,
    rate_limiter: Data<RateLimiter>,
) -> Result<HttpResponse> {
    // 1. Extract email from payload
    let email: String = req.into_inner().email;

    /*
     * [ DON'T SEND A NON EXISTENCE EMAIL ERROR MESSAGE ]
     */
    // 2. Check if email exists
    if let Ok(user) = repo.user_service.find_by_email(&email).await {
        let user_id = user.id.unwrap_or_default();

        // Check rate limiting
        rate_limiter.check_rate_limit(&user)?;

        // 3. If exists: invalidate existing tokens
        repo.password_reset_token_service.revoke(user_id).await?;

        // 4. Generate a new token + hash
        // try to use something like: Utils::generate_token(32).hash()
        let token = Utils::generate_token(32);
        let hashed_token = Utils::hash_token(&token);

        // 5. If exists: store token record
        let otp = PasswordResetTokens::default()
            .with_user_id(user_id)
            .with_token_hash(hashed_token);
        repo.password_reset_token_service.insert(otp).await?;

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
    repo: Data<ServiceManager>,
    query: Query<TokenQuery>,
) -> Result<HttpResponse> {
    // 1. Extract token from URL
    let token: &str = &query.token;
    let hash = Utils::hash_token(token);

    // 2. Checks the database for a matching token
    let reset_token = repo.password_reset_token_service.find(hash).await?;

    // 3. Verify token isn't expired or already used
    if !reset_token.valid {
        return Err(Error::TokenAlreadyUsed);
    }
    if Utc::now() > reset_token.expired_at {
        let token_id = reset_token.id.unwrap_or_default();
        repo.password_reset_token_service
            .invalidate(token_id)
            .await?;
        return Err(Error::TokenExpired);
    }

    // 4. Check user account: blocked | suspended
    let user_id = reset_token.user_id;
    let user = repo.user_service.find(user_id).await?;
    if user.account_locked {
        return Err(Error::AccountSuspended);
    }

    Ok(HttpResponse::Ok().json("Password reset initiated"))
}

async fn update_password(
    claims: Claims,
    repo: Data<ServiceManager>,
    password: Query<String>,
) -> Result<HttpResponse> {
    // 1. Validate token

    // 2. Find User
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();
    let user: User = repo.user_service.find(user_id).await?;

    // 3. Ensure user account is active
    if user.account_locked {
        tracing::warn!("Blocked user attempted to update password: {}", user_id);
        return Err(Error::AccountSuspended);
    }

    // 4. Ensure password is different then previous
    if Utils::verify_password(&password, &user.password) {
        tracing::warn!(
            "Current password is similair to previous password, user: {}",
            user_id
        );
        return Err(Error::InvalidCredentials);
    }

    // 5. Hash new password using argon2
    let hashed_password = Utils::hash_password(&password)?;
    repo.user_service
        .update_password(user_id, hashed_password)
        .await?;

    // 6. Mark token as used (used_at = now)

    // 6.5. Update user.last_password_reset to now()
    repo.user_service
        .update_last_password_reset(user_id)
        .await?;

    // 7. invalidate passwordTokens related to user
    repo.password_reset_token_service.revoke(user_id).await?;

    repo.auth_service
        .logout(user_id)
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
