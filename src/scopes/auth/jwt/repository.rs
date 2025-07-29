use async_trait::async_trait;
use futures::TryStreamExt;
use mockall::automock;
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    results::{InsertOneResult, UpdateResult},
    Collection, Cursor, Database,
};

use super::model::RefreshToken;

pub struct DatabaseTokenRepo {
    collection: Collection<RefreshToken>,
}
impl DatabaseTokenRepo {
    pub fn new(db: &Database) -> Self {
        const COLL_NAME: &str = "refresh-token";
        DatabaseTokenRepo {
            collection: db.collection::<RefreshToken>(COLL_NAME),
        }
    }
}

#[automock]
#[async_trait]
pub trait RefreshTokenRepo: Send + Sync {
    async fn insert(&self, token: RefreshToken) -> Result<InsertOneResult, Error>;
    async fn invalidate(&self, token_id: ObjectId) -> Option<RefreshToken>;
    async fn revoke(&self, user_id: ObjectId) -> Result<UpdateResult, Error>;
    async fn find(&self, user_id: ObjectId) -> Option<Vec<RefreshToken>>;
}

#[async_trait]
impl RefreshTokenRepo for DatabaseTokenRepo {
    async fn insert(&self, token: RefreshToken) -> Result<InsertOneResult, Error> {
        let token = self.collection.insert_one(token).await?;

        Ok(token)
    }
    async fn invalidate(&self, token_id: ObjectId) -> Option<RefreshToken> {
        let filter = doc! {"_id": token_id};
        let update = doc! { "$set": doc! {"valid": false} };

        self.collection
            .find_one_and_update(filter, update)
            .await
            .ok()?
    }
    async fn revoke(&self, user_id: ObjectId) -> Result<UpdateResult, Error> {
        let filter = doc! {"userId": user_id};
        let update = doc! { "$set": doc! {"valid": false} };
        let token_detail = self.collection.update_many(filter, update).await?;

        Ok(token_detail)
    }
    async fn find(&self, user_id: ObjectId) -> Option<Vec<RefreshToken>> {
        let filter = doc! {"userId": user_id};
        let cursor: Cursor<RefreshToken> = self.collection.find(filter).await.ok()?;

        let tokens: Vec<RefreshToken> = cursor.try_collect().await.ok()?;

        Some(tokens)
    }
}
