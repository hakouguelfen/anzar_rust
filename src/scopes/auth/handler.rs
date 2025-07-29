use actix_web::{
    web::{self, Data, Json, Query},
    HttpResponse, Scope,
};
use chrono::{Duration, Local, Utc};
use mongodb::bson::oid::ObjectId;
use tracing_subscriber::fmt::format;

use crate::{
    core::{rate_limiter::RateLimiter, repository::repository_manager::RepositoryManager},
    scopes::auth::Error,
};

use super::{
    email::manager::Email,
    models::{EmailRequest, LoginRequest, TokenQuery},
    user::repository::UserRepo,
    utils::{AuthenticationHasher, Utils},
    RefreshTokenRepo,
};
use super::{error::Result, models::AuthPayload};
use super::{extenstion::AuthResponseTrait, repository};
use super::{reset_password::model::PasswordResetTokens, Claims};
use super::{user::User, OTPRepo};

#[tracing::instrument(
    name = "Login user",
    skip(req, repo),
    fields(user_email = %req.email)
)]
async fn login(req: Json<LoginRequest>, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user: User = repository::check_credentials(&repo, req.into_inner()).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::set_auth_headers(tokens, user.as_response())))?
}

#[tracing::instrument(
    name = "Register user",
    skip(req, repo),
    fields(user_email = %req.email, user_name = %req.username)
)]
async fn register(req: Json<User>, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user: User = repository::create_user(&repo, req.into_inner()).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::set_auth_headers(tokens, user.as_response())))?
}

#[tracing::instrument(
    name = "Regenerate user accessToken",
    skip(payload, repo),
    fields(user_id = %payload.user_id)
)]
async fn refresh_token(
    payload: AuthPayload,
    repo: Data<RepositoryManager>,
) -> Result<HttpResponse> {
    // NOTE: maybe save valid tokens to user doc
    let user: User = repository::validate_token(&repo, payload).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(tokens)))?
}

#[tracing::instrument(
    name = "Logout user",
    skip(claims, repo),
    fields(user_id = %claims.sub)
)]
async fn logout(claims: Claims, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();
    repository::logout(repo, user_id)
        .await
        .map(|user| Ok(HttpResponse::Ok().json(user)))?
}

#[tracing::instrument(name = "Forgot password", skip(repo, rate_limiter))]
async fn forgot_password(
    req: Json<EmailRequest>,
    repo: Data<RepositoryManager>,
    rate_limiter: Data<RateLimiter>,
) -> Result<HttpResponse> {
    // 1. Extract email from payload
    let email: String = req.into_inner().email;

    /*
     * [ DON'T SEND A NON EXISTENCE EMAIL ERROR MESSAGE ]
     *
     * If an application says whether or not an email address is registered,
     * an attacker could potentially know if a user has an account.
     * This gives them one more piece of information to use against you.
     */
    // 2. Check if email exists
    if let Ok(user) = repository::find_by_email(&repo, &email).await {
        // Check rate limiting
        rate_limiter.check_rate_limit(&user)?;

        // 3. If exists: invalidate existing tokens

        // 4. Generate a new token + hash
        let token = Utils::generate_token(32);
        let hashed_token = Utils::hash_token(&token);

        // 5. If exists: store token record
        let otp = PasswordResetTokens::default()
            .with_user_id(user.id.unwrap())
            .with_token_hash(hashed_token);

        let _ = repo.otp_repo.insert(otp).await.map_err(|e| {
            tracing::error!("Failed to insert password reset token to database: {:?}", e);
            Error::TokenCreationFailed
        });

        // 6. If exists: send email: exp-> api/reset-password?token=xxxxxxx
        let body = format!(
            include_str!("email/templates/password_reset.html"),
            &user.username, &token, &token
        );

        Email::default()
            .to("hakoudev@gmail.com")
            .send(&body)
            .await
            .map_err(|e| {
                dbg!(&e);
                tracing::error!("Failed to send password reset email: {:?}", e);
                Error::EmailSendFailed
            })?;

        // 7. Increment user's reset attempt count
        let user_id = user.id.unwrap_or_default();
        let _ = repo
            .user_repo
            .increment_reset_count(user_id)
            .await
            .ok_or_else(|| {
                tracing::error!("Failed to increment reset counter for user: {}", user_id);
                Error::DatabaseError
            })?;
    }

    Ok(HttpResponse::Ok().json("if email exists a link will be sent"))
}

async fn reset_password(
    repo: Data<RepositoryManager>,
    query: Query<TokenQuery>,
) -> Result<HttpResponse> {
    // 1. Extract token from URL
    let token: &str = &query.token;
    let computed_hash = Utils::hash_token(token);

    // 2. Checks the database for a matching token
    let password_reset_token = repo.otp_repo.find(computed_hash).await.ok_or_else(|| {
        tracing::error!("Failed to find token");
        Error::TokenNotFound
    })?;

    // 3. Verify token isn't expired or already used
    if !password_reset_token.valid {
        // TODO: send an email indicating a not valid token
        return Err(Error::TokenAlreadyUsed);
    }
    if Utc::now() > password_reset_token.expired_at {
        repo.token_repo
            .invalidate(password_reset_token.id.unwrap())
            .await
            .ok_or_else(|| {
                tracing::error!("Failed to invalidate token");
                Error::DatabaseError
            })?;
        // TODO: send an email indicating a not valid token
        return Err(Error::TokenExpired);
    }

    // 4. Check user account: blocked | suspended
    let user_id = password_reset_token.user_id;

    match repo.user_repo.find_by_id(user_id).await {
        Some(user) if user.account_locked => Err(Error::AccountSuspended),
        Some(_) => Ok(HttpResponse::Ok().json("Password reset initiated")),
        None => Err(Error::UserNotFound),
    }
}
async fn update_password(
    claims: Claims,
    repo: Data<RepositoryManager>,
    password: Query<String>,
) -> Result<HttpResponse> {
    // 0. Validate token

    // 1. Extract userId
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();

    // 2. Get user by user_id
    let user: User = repo.user_repo.find_by_id(user_id).await.ok_or_else(|| {
        tracing::error!("Failed to find user by id: {}", user_id);
        Error::UserNotFound
    })?;

    // 3. Ensure user account is active
    if user.account_locked {
        tracing::warn!("Blocked user attempted password update: {}", user_id);
        return Err(Error::AccountSuspended);
    }

    // 4. Check if new password is different from current
    if Utils::verify_password(&password, &user.password) {
        tracing::warn!(
            "Current password is similair to previous password, user: {}",
            user_id
        );
        return Err(Error::InvalidCredentials);
    }

    // 5. Hash new password using argon2
    let hashed_password = Utils::hash_password(&password)?;
    let _ = repository::update_password(repo.clone(), user_id, hashed_password)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update password: {:?}", e);
            Error::PasswordUpdateFailed
        })?;

    // 6. Mark token as used (used_at = now)

    // 6.5. Update user.last_password_reset to now()
    repo.user_repo
        .update_last_password_reset(user_id, Utc::now())
        .await
        .ok_or_else(|| {
            tracing::error!("Failed to update laste password reset time");
            Error::DatabaseError
        })?;

    // 7. invalidate passwordTokens related to user
    let _ = repo.otp_repo.revoke(user_id).await.map_err(|e| {
        tracing::error!("Failed to revoke password tokens: {:?}", e);
        Error::TokenRevocationFailed
    });

    repository::logout(repo, user_id)
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
        .route("/update-password", web::get().to(update_password))
}
