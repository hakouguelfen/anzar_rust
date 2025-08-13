use chrono::Utc;
use mongodb::{Database, bson::oid::ObjectId};

use crate::scopes::{
    auth::{Error, Result},
    user::{
        User,
        repository::{DatabaseUserRepo, UserRepo},
    },
};

#[derive(Debug)]
pub struct UserService {
    repository: DatabaseUserRepo,
}

impl UserService {
    pub fn new(db: &Database) -> Self {
        Self {
            repository: DatabaseUserRepo::new(db),
        }
    }

    pub async fn find(&self, user_id: ObjectId) -> Result<User> {
        self.repository.find_by_id(user_id).await.ok_or_else(|| {
            tracing::error!("Failed to find user by id: {}", user_id);
            Error::UserNotFound
        })
    }

    #[tracing::instrument(name = "Find user by email", skip(email))]
    pub async fn find_by_email(&self, email: &str) -> Result<User> {
        self.repository.find_by_email(email).await.ok_or_else(|| {
            tracing::error!("Failed to find user by email");
            Error::UserNotFound
        })
    }

    #[tracing::instrument(name = "Create user account", skip(user))]
    pub async fn insert(&self, user: &User) -> Result<ObjectId> {
        let insert_result = self.repository.create_user(user).await.map_err(|e| {
            tracing::error!("Failed to insert new user to Database: {:?}", e);
            Error::UserCreationFailure
        })?;

        Ok(insert_result.inserted_id.as_object_id().unwrap_or_default())
    }

    #[tracing::instrument(name = "Update Password", skip(user_id))]
    pub async fn update_password(&self, user_id: ObjectId, password: String) -> Result<User> {
        let user = self
            .repository
            .update_password(user_id, password)
            .await
            .ok_or_else(|| db_error("update password", user_id))?;

        Ok(user)
    }

    #[tracing::instrument(name = "Forgot password", skip(user_id))]
    pub async fn update_reset_window(&self, user_id: ObjectId) -> Result<()> {
        self.repository
            .update_reset_window(user_id)
            .await
            .ok_or_else(|| db_error("reset window start", user_id))?;

        Ok(())
    }

    #[tracing::instrument(name = "Forgot password", skip(user_id))]
    pub async fn increment_reset_count(&self, user_id: ObjectId) -> Result<User> {
        self.repository
            .increment_reset_count(user_id)
            .await
            .ok_or_else(|| db_error("reset counter", user_id))
    }

    #[tracing::instrument(name = "Update password", skip(user_id))]
    pub async fn update_last_password_reset(&self, user_id: ObjectId) -> Result<User> {
        self.repository
            .update_last_password_reset(user_id, Utc::now())
            .await
            .ok_or_else(|| db_error("update last password reset time", user_id))
    }
}

fn db_error(msg: &str, user_id: ObjectId) -> Error {
    tracing::error!("Failed to {} for user: {}", msg, user_id);
    Error::DatabaseError
}
