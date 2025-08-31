use chrono::Utc;
use mongodb::{
    Database,
    bson::{doc, oid::ObjectId},
};

use crate::{
    adapters::mongodb_adapter::{MongodbAdapter, MongodbAdapterTrait},
    scopes::{
        auth::{Error, Result},
        user::User,
    },
};

#[derive(Debug, Clone)]
pub struct UserService {
    mongodb_adapter: MongodbAdapter<User>,
}

impl UserService {
    pub fn new(db: &Database) -> Self {
        Self {
            mongodb_adapter: MongodbAdapter::new(db, "user"),
        }
    }

    pub async fn find(&self, user_id: ObjectId) -> Result<User> {
        let filter = doc! {"_id": user_id};

        self.mongodb_adapter.find_one(filter).await.ok_or_else(|| {
            tracing::error!("Failed to find user by id: {}", user_id);
            Error::UserNotFound
        })
    }

    pub async fn find_by_email(&self, email: &str) -> Result<User> {
        let filter = doc! {"email": email};
        self.mongodb_adapter.find_one(filter).await.ok_or_else(|| {
            tracing::error!("Failed to find user by email");
            Error::UserNotFound
        })
    }

    pub async fn insert(&self, user: &User) -> Result<ObjectId> {
        let insert_result = self
            .mongodb_adapter
            .insert(user.to_owned())
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert new user to Database: {:?}", e);
                Error::UserCreationFailure
            })?;

        Ok(insert_result.inserted_id.as_object_id().unwrap_or_default())
    }

    pub async fn update_password(&self, user_id: ObjectId, password: String) -> Result<User> {
        let filter = doc! {"_id": user_id};
        let update = doc! { "$set": doc! {"password": password} };

        let user = self
            .mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("update password", user_id))?;

        Ok(user)
    }

    pub async fn update_reset_window(&self, user_id: ObjectId) -> Result<()> {
        let filter = doc! {"_id": user_id};
        let update = doc! { "$set": doc! {"passwordResetWindowStart": Utc::now().to_rfc3339()} };
        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("reset window start", user_id))?;

        Ok(())
    }

    pub async fn increment_reset_count(&self, user_id: ObjectId) -> Result<User> {
        let filter = doc! {"_id": user_id};
        let update = doc! { "$inc": doc! {"passwordResetCount": 1} };
        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("reset counter", user_id))
    }

    pub async fn reset_password_state(&self, user_id: ObjectId) -> Result<User> {
        let filter = doc! {"_id": user_id};
        let update = doc! {
            "$set": doc! {
                "lastPasswordReset": Utc::now().to_rfc3339(),
                "passwordResetCount": 0,
                "failedResetAttempts": 0
            }
        };
        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("update last password reset time", user_id))
    }
}

fn db_error(msg: &str, user_id: ObjectId) -> Error {
    tracing::error!("Failed to {} for user: {}", msg, user_id);
    Error::DatabaseError
}
