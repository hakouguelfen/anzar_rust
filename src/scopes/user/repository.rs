use std::sync::Arc;

use async_trait::async_trait;
use log::info;
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
        let user = self.collection.find_one(filter).await.ok()?;

        user
    }
    async fn create_user(&self, user: &User) -> Result<InsertOneResult, Error> {
        info!("user creation in proccess");
        let response = self.collection.insert_one(user).await?;
        info!("user created successfully, user_id: [{}]", user.id.unwrap());

        Ok(response)
    }
    async fn find_by_id(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let user_detail = self.collection.find_one(filter).await.ok()?;

        user_detail
    }
    async fn activate_account(&self, id: ObjectId) -> Option<User> {
        let filter = doc! {"_id": id};
        let update = doc! { "$set": doc! {"isPremium": true} };
        let user_detail = self
            .collection
            .find_one_and_update(filter, update)
            .await
            .ok()?;

        user_detail
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
    match db.list_collection_names().await {
        Ok(collections) => {
            dbg!(&collections);

            if collections.contains(&"user".to_string()) {
                let options = IndexOptions::builder().unique(true).build();
                let model = IndexModel::builder()
                    .keys(doc! { "email": 1 })
                    .options(options)
                    .build();

                db.collection::<User>("user").create_index(model).await?;
            }
        }
        Err(err) => {
            dbg!(err);
        }
    };

    Ok(())
}
