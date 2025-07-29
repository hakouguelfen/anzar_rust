use actix_web::web::Data;
use chrono::{Duration, Local};
use mongodb::bson::oid::ObjectId;

use crate::core::repository::repository_manager::RepositoryManager;

use super::error::{Error, Result};
use super::jwt::model::RefreshToken;
use super::models::{AuthPayload, LoginRequest};
use super::tokens::{JwtEncoderBuilder, Tokens};
use super::user::{repository::UserRepo, User};
use super::RefreshTokenRepo;

use super::utils::{AuthenticationHasher, Utils};

#[tracing::instrument(name = "Check user credentials", skip(req, repo))]
pub async fn check_credentials(repo: &Data<RepositoryManager>, req: LoginRequest) -> Result<User> {
    let user: User = find_by_email(repo, &req.email).await?;

    match Utils::verify_password(&req.password, &user.password) {
        true => Ok(user),
        false => {
            tracing::error!("Failed to verify password");
            Err(Error::InvalidCredentials)
        }
    }
}

#[tracing::instrument(name = "Find user by email", skip(email, repo))]
pub async fn find_by_email(repo: &Data<RepositoryManager>, email: &str) -> Result<User> {
    let user = repo.user_repo.find_by_email(email).await.ok_or_else(|| {
        tracing::error!("Failed to find user by email");
        Error::InvalidCredentials
    })?;

    Ok(user)
}

#[tracing::instrument(name = "Create user", skip(req, repo))]
pub async fn create_user(repo: &Data<RepositoryManager>, req: User) -> Result<User> {
    let hashed_password = Utils::hash_password(&req.password)?;
    let mut new_user: User = User::new(req).with_password(hashed_password);

    let insert_result = repo.user_repo.create_user(&new_user).await.map_err(|e| {
        tracing::error!("Failed to insert new user to Database: {:?}", e);
        Error::UserCreationFailure
    })?;

    let user_id: ObjectId = insert_result.inserted_id.as_object_id().unwrap_or_default();
    new_user.with_id(user_id);

    Ok(new_user)
}

#[tracing::instrument(name = "Create user", skip(payload, repo))]
pub async fn validate_token(repo: &Data<RepositoryManager>, payload: AuthPayload) -> Result<User> {
    if payload.user_id.is_empty() || payload.refresh_token.is_empty() {
        tracing::error!(
            "Failed to regenerate accessToken because (user_id | refresh_token) is empty"
        );
        return Err(Error::MissingCredentials);
    }

    let user_id: ObjectId = ObjectId::parse_str(&payload.user_id).map_err(|e| {
        tracing::error!("Failed to parse user_id to ObjectId: {:?}", e);
        Error::InvalidCredentials
    })?;

    let user: User = repo.user_repo.find_by_id(user_id).await.ok_or_else(|| {
        tracing::error!("Failed to find user by id: {}", user_id);
        Error::UserNotFound
    })?;

    // 4. Check if user account is active
    // if user.is_blocked || user.is_suspended {
    //     tracing::warn!("Blocked user attempted authentication: {}", user_id);
    //     return Err(Error::AccountSuspended);
    // }

    let tokens: Vec<RefreshToken> = repo.token_repo.find(user_id).await.ok_or_else(|| {
        tracing::error!("Failed to find refreshToken by user_id: {}", user_id);
        Error::InvalidToken
    })?;

    let refresh_token = tokens
        .into_iter()
        .find(|token| Utils::verify_token(&payload.refresh_token, &token.hash))
        .ok_or_else(|| {
            tracing::warn!("Invalid refresh token for user: {}", user_id);
            Error::InvalidToken
        })?;

    if !refresh_token.valid {
        tracing::error!(
            "Invalid refresh token detected for user: {} - revoking all tokens",
            user_id
        );
        // Security: revoke all tokens for this user
        if let Err(e) = repo.token_repo.revoke(user_id).await {
            tracing::error!("Failed to revoke tokens after security breach: {:?}", e);
        }
        return Err(Error::InvalidToken);
    }

    // if refresh token is valid, invalidated then issue a new pair of tokens
    repo.token_repo
        .invalidate(refresh_token.id.unwrap_or_default())
        .await
        .ok_or_else(|| {
            tracing::error!(
                "Failed to invalidate refreshToken: {}",
                refresh_token.id.unwrap_or_default()
            );
            Error::TokenRevocationFailed
        })?;

    Ok(user)
}

#[tracing::instrument(name = "Remove refreshToken", skip(user_id, repo))]
pub async fn logout(repo: Data<RepositoryManager>, user_id: ObjectId) -> Result<User> {
    let user = repo
        .user_repo
        .remove_refresh_token(user_id)
        .await
        .ok_or_else(|| {
            tracing::error!(
                "Failed to remove refresh token from user document for user_id: {}",
                user_id
            );
            Error::DatabaseError
        })?;

    // TODO: invalidate all user tokens
    let user_id: ObjectId = user.id.unwrap_or_default();
    repo.token_repo.revoke(user_id).await.map_err(|e| {
        tracing::error!(
            "Failed to revoke all tokens for user_id {}: {:?}",
            user_id,
            e
        );
        Error::DatabaseError
    })?;

    tracing::info!("Successfully logged out user: {}", user_id);
    Ok(user)
}

#[tracing::instrument(name = "Issue authentication tokens", skip(user, repo))]
pub async fn issue_and_save_tokens(repo: &Data<RepositoryManager>, user: &User) -> Result<Tokens> {
    let user_id: ObjectId = user.id.unwrap_or_default();

    let tokens: Tokens = JwtEncoderBuilder::default()
        .user_id(user_id.to_string())
        .role(user.role.clone())
        .build()
        .inspect_err(|e| tracing::error!("Failed to generate authentication tokens: {:?}", e))?;

    let hashed_refresh_token = Utils::hash_token(&tokens.refresh_token);

    let refresh_token = RefreshToken::default()
        .with_user_id(user_id)
        .with_hash(hashed_refresh_token)
        .with_issued_at(Local::now().timestamp() as usize)
        .with_expire_at((Local::now() + Duration::days(30)).timestamp() as usize);

    let _ = repo.token_repo.insert(refresh_token).await.map_err(|e| {
        tracing::error!("Failed to insert refreshToken to database: {:?}", e);
        Error::TokenCreationFailed
    })?;

    Ok(tokens)
}

#[tracing::instrument(name = "Update Password", skip(user_id, repo))]
pub async fn update_password(
    repo: Data<RepositoryManager>,
    user_id: ObjectId,
    password: String,
) -> Result<User> {
    let hashed_password = Utils::hash_password(&password)?;
    let user = repo
        .user_repo
        .update_password(user_id, hashed_password)
        .await
        .ok_or_else(|| {
            tracing::error!("Failed to update password for user: {}", user_id);
            Error::DatabaseError
        })?;

    Ok(user)
}
