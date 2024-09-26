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

pub async fn check_credentials(repo: &Data<RepositoryManager>, req: LoginRequest) -> Result<User> {
    let user: User = find_by_email(&repo, req.email).await?;

    if !verify(&req.password, &user.password).unwrap_or(false) {
        return Err(Error::WrongCredentials);
    }

    Ok(user)
}

pub async fn find_by_email(repo: &Data<RepositoryManager>, email: String) -> Result<User> {
    repo.user_repo
        .find_by_email(&email)
        .await
        .ok_or_else(|| Error::WrongCredentials)
}

pub async fn create_user(repo: &Data<RepositoryManager>, req: User) -> Result<User> {
    let hashed = hash(&req.password, DEFAULT_COST).map_err(|_| Error::HashingFailure)?;

    let mut new_user: User = User::new(req).with_password(hashed);

    let insert_result = repo
        .user_repo
        .create_user(&new_user)
        .await
        .map_err(|_| Error::UserCreationFailure)?;

    let user_id: ObjectId = insert_result.inserted_id.as_object_id().unwrap_or_default();
    new_user.with_id(user_id);

    Ok(new_user)
}

pub async fn validate_token(repo: &Data<RepositoryManager>, payload: AuthPayload) -> Result<User> {
    if payload.user_id.is_empty() || payload.refresh_token.is_empty() {
        return Err(Error::MissingCredentials);
    }

    let user_id: ObjectId =
        ObjectId::parse_str(&payload.user_id).map_err(|_| Error::WrongCredentials)?;
    let user: User = repo
        .user_repo
        .find_by_id(user_id)
        .await
        .ok_or_else(|| Error::WrongCredentials)?;

    let tokens: Vec<RefreshToken> = repo
        .token_repo
        .find(user_id)
        .await
        .ok_or_else(|| Error::BadRequest)?;

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
        let _ = repo.token_repo.revoke(user_id).await;
        return Err(Error::InvalidToken);
    }

    repo.token_repo
        .invalidate(refresh_token.id.unwrap())
        .await
        .ok_or(Error::InvalidToken)?;

    Ok(user)
}

pub async fn logout(repo: Data<RepositoryManager>, user_id: ObjectId) -> Result<User> {
    let user = repo
        .user_repo
        .remove_refresh_token(user_id)
        .await
        .ok_or_else(|| Error::InternalError)?;
    Ok(user)
}

pub async fn issue_and_save_tokens(repo: &Data<RepositoryManager>, user: &User) -> Result<Tokens> {
    let user_id: ObjectId = user.id.unwrap_or_default();

    let tokens: Tokens = JwtEncoderBuilder::new()
        .sub(user_id.to_string())
        .role(user.role.clone())
        .build()?;

    let hashed_refresh_token = hash_token(&tokens.refresh_token);

    let refresh_token = RefreshToken::new()
        .with_user_id(user_id)
        .with_hash(hashed_refresh_token)
        .with_issued_at(Local::now().timestamp() as usize)
        .with_expire_at((Local::now() + Duration::days(30)).timestamp() as usize);

    let _ = repo
        .token_repo
        .create(refresh_token)
        .await
        .map_err(|_| Error::TokenCreation)?;

    Ok(tokens)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn verify_token(token: &str, stored_hash: &str) -> bool {
    let calculated_hash = hash_token(token);
    calculated_hash == stored_hash
}
