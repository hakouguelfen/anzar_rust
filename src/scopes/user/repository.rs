use async_trait::async_trait;
use chrono::Utc;
use mockall::automock;
use mongodb::{
    Collection, Database, IndexModel,
    bson::{doc, oid::ObjectId},
    error::Error,
    options::{IndexOptions, ReturnDocument},
    results::InsertOneResult,
};

use super::models::User;

#[derive(Debug, Clone)]
pub struct DatabaseUserRepo {
    collection: Collection<User>,
}
impl DatabaseUserRepo {
    pub fn new(db: &Database) -> Self {
        const COLL_NAME: &str = "user";
        DatabaseUserRepo {
            collection: db.collection::<User>(COLL_NAME),
        }
    }
}

#[automock]
#[async_trait]
pub trait UserRepo: Send + Sync {
    async fn create_user(&self, user: &User) -> Result<InsertOneResult, Error>;
    async fn find_by_email(&self, email: &str) -> Option<User>;
    async fn find_by_id(&self, id: ObjectId) -> Option<User>;
    async fn update_password(&self, id: ObjectId, password: String) -> Option<User>;
    async fn increment_reset_count(&self, id: ObjectId) -> Option<User>;
    async fn update_reset_window(&self, id: ObjectId) -> Option<User>;
    async fn reset_password_state(&self, id: ObjectId) -> Option<User>;
}

#[async_trait]
impl UserRepo for DatabaseUserRepo {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        let filter = doc! {"email": email};

        self.collection.find_one(filter).await.ok()?
    }
    async fn create_user(&self, user: &User) -> Result<InsertOneResult, Error> {
        self.collection.insert_one(user).await
    }
    async fn find_by_id(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};

        self.collection.find_one(filter).await.ok()?
    }
    async fn update_password(&self, id: ObjectId, password: String) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$set": doc! {"password": password} };

        self.collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }
    async fn increment_reset_count(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$inc": doc! {"passwordResetCount": 1} };

        self.collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }
    async fn update_reset_window(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$set": doc! {"passwordResetWindowStart": Utc::now().to_rfc3339()} };

        self.collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }

    async fn reset_password_state(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! {
            "$set": doc! {
                "lastPasswordReset": Utc::now().to_rfc3339(),
                "passwordResetCount": 0,
                "failedResetAttempts": 0
            }
        };

        self.collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }
}

pub async fn create_unique_email_index(db: &Database) -> Result<(), mongodb::error::Error> {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! { "email": 1 })
        .options(options)
        .build();

    db.collection::<User>("user").create_index(model).await?;

    Ok(())
}
