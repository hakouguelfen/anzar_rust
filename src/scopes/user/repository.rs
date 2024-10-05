use std::sync::Arc;

use async_trait::async_trait;
use mockall::automock;
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    options::{IndexOptions, ReturnDocument},
    results::InsertOneResult,
    Collection, Database, IndexModel,
};

use super::models::User;

pub struct DatabaseUserRepo {
    collection: Collection<User>,
}
impl DatabaseUserRepo {
    pub fn new(db: &Arc<Database>) -> Self {
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
    async fn activate_account(&self, id: ObjectId) -> Option<User>;
    async fn remove_refresh_token(&self, id: ObjectId) -> Option<User>;
}

#[async_trait]
impl UserRepo for DatabaseUserRepo {
    async fn find_by_email(&self, email: &str) -> Option<User> {
        let filter = doc! {"email": email};

        self.collection.find_one(filter).await.ok()?
    }
    async fn create_user(&self, user: &User) -> Result<InsertOneResult, Error> {
        log::debug!("User Creation in Proccess ...");

        self.collection
            .insert_one(user)
            .await
            .inspect(|_| {
                log::debug!("User Creation Successeded");
            })
            .inspect_err(|err| {
                log::debug!("User Creation Failed {err}");
            })
    }
    async fn find_by_id(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};

        self.collection.find_one(filter).await.ok()?
    }
    async fn activate_account(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$set": doc! {"isPremium": true} };

        self.collection
            .find_one_and_update(filter, update)
            .await
            .ok()?
    }
    async fn remove_refresh_token(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$unset": doc! {"refreshToken": ""} };

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
