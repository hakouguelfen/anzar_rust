use actix_web::web::Data;
use bcrypt::{self, hash, verify, DEFAULT_COST};
use chrono::{Duration, Local};
use mongodb::bson::oid::ObjectId;

use hex;
use sha3::{Digest, Sha3_256};

use crate::core::repository::repository_manager::RepositoryManager;

use super::error::{Error, Result};
use super::model::RefreshToken;
use super::models::{AuthPayload, LoginRequest};
use super::tokens::{JwtEncoderBuilder, Tokens};
use super::user::repository::UserRepo;
use super::user::User;
use super::RefreshTokenRepo;

#[tracing::instrument(name = "Check user credentials", skip(req, repo))]
pub async fn check_credentials(repo: &Data<RepositoryManager>, req: LoginRequest) -> Result<User> {
    let user: User = find_by_email(repo, req.email).await?;

    if !verify(&req.password, &user.password).unwrap_or(false) {
        tracing::error!("Failed to verify password");
        return Err(Error::WrongCredentials);
    }

    Ok(user)
}

#[tracing::instrument(name = "Find user by email", skip(email, repo))]
pub async fn find_by_email(repo: &Data<RepositoryManager>, email: String) -> Result<User> {
    let s = repo.user_repo.find_by_email(&email).await.ok_or_else(|| {
        tracing::error!("Failed to find user by email");
        Error::WrongCredentials
    })?;

    Ok(s)
}

#[tracing::instrument(name = "Create user", skip(req, repo))]
pub async fn create_user(repo: &Data<RepositoryManager>, req: User) -> Result<User> {
    let hashed = hash(&req.password, DEFAULT_COST).map_err(|e| {
        tracing::error!("Failed to hash user password: {:?}", e);
        Error::HashingFailure
    })?;

    let mut new_user: User = User::new(req).with_password(hashed);

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
        Error::WrongCredentials
    })?;

    let user: User = repo.user_repo.find_by_id(user_id).await.ok_or_else(|| {
        tracing::error!("Failed to find user by id: {}", user_id);
        Error::WrongCredentials
    })?;

    let tokens: Vec<RefreshToken> = repo.token_repo.find(user_id).await.ok_or_else(|| {
        tracing::error!("Failed to find refreshToken by user_id: {}", user_id);
        Error::BadRequest
    })?;

    let mut token_data: Option<RefreshToken> = None;
    for token in tokens {
        if verify_token(&payload.refresh_token, &token.hash) {
            token_data = Some(token);
            break;
        }
    }

    let refresh_token = token_data.ok_or(Error::InvalidToken)?;

    if !refresh_token.valid {
        // TODO: send an email indicating a possible breach
        tracing::error!("Failed to regenerate accessToken (refreshToken is invalid)");
        tracing::info!(
            "Revoke all refreshTokens related to user: {}",
            refresh_token.user_id.unwrap_or_default()
        );
        let _ = repo.token_repo.revoke(user_id).await;
        return Err(Error::InvalidToken);
    }

    repo.token_repo
        .invalidate(refresh_token.id.unwrap_or_default())
        .await
        .ok_or_else(|| {
            tracing::error!(
                "Failed to invalidate refreshToken: {}",
                refresh_token.id.unwrap_or_default()
            );
            Error::InvalidToken
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
            tracing::error!("Failed to logout and remove refreshToken from Database");
            Error::InternalError
        })?;

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

    let hashed_refresh_token = hash_token(&tokens.refresh_token);

    let refresh_token = RefreshToken::default()
        .with_user_id(user_id)
        .with_hash(hashed_refresh_token)
        .with_issued_at(Local::now().timestamp() as usize)
        .with_expire_at((Local::now() + Duration::days(30)).timestamp() as usize);

    let _ = repo.token_repo.insert(refresh_token).await.map_err(|e| {
        tracing::error!("Failed to insert refreshToken to database: {:?}", e);
        Error::TokenCreation
    })?;

    Ok(tokens)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn verify_token(token: &str, stored_hash: &str) -> bool {
    hash_token(token) == stored_hash
}
