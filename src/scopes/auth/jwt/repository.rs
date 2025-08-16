use async_trait::async_trait;
use chrono::Utc;
use mockall::automock;
use mongodb::{
    Collection, Database,
    bson::{doc, oid::ObjectId},
    error::Error,
    results::{InsertOneResult, UpdateResult},
};

use crate::scopes::auth::jwt::model::RefreshTokenFilter;

use super::model::RefreshToken;

#[derive(Debug)]
pub struct DatabaseJWTRepo {
    collection: Collection<RefreshToken>,
}
impl DatabaseJWTRepo {
    pub fn new(db: &Database) -> Self {
        const COLL_NAME: &str = "refresh-token";
        DatabaseJWTRepo {
            collection: db.collection::<RefreshToken>(COLL_NAME),
        }
    }
}

#[automock]
#[async_trait]
pub trait JWTRepo: Send + Sync {
    async fn insert(&self, token: RefreshToken) -> Result<InsertOneResult, Error>;
    async fn invalidate(&self, jti: String) -> Result<Option<RefreshToken>, Error>;
    async fn revoke(&self, user_id: ObjectId) -> Result<UpdateResult, Error>;
    async fn find_by_filter(&self, filter: RefreshTokenFilter) -> Option<RefreshToken>;
    async fn find(&self, id: ObjectId) -> Option<RefreshToken>;
    async fn find_by_jti(&self, jti: String) -> Option<RefreshToken>;
}

#[async_trait]
impl JWTRepo for DatabaseJWTRepo {
    async fn insert(&self, token: RefreshToken) -> Result<InsertOneResult, Error> {
        let token = self.collection.insert_one(token).await?;

        Ok(token)
    }
    async fn invalidate(&self, jti: String) -> Result<Option<RefreshToken>, Error> {
        let filter = doc! {"jti": jti};
        let update = doc! { "$set": doc! {"valid": false} };

        self.collection.find_one_and_update(filter, update).await
    }
    async fn revoke(&self, user_id: ObjectId) -> Result<UpdateResult, Error> {
        let filter = doc! {"userId": user_id};
        let update = doc! { "$set": doc! {"valid": false} };
        let token_detail = self.collection.update_many(filter, update).await?;

        Ok(token_detail)
    }
    async fn find_by_filter(&self, filter: RefreshTokenFilter) -> Option<RefreshToken> {
        let filter = doc! {
            "jti": filter.jti,
            "userId": filter.user_id,
            "hash": filter.hash,
            "valid": filter.valid
        };
        let update = doc! { "$set": doc! { "valid": false, "usedAt": Utc::now().to_string() } };

        self.collection
            .find_one_and_update(filter, update)
            .await
            .ok()?
    }

    async fn find_by_jti(&self, jti: String) -> Option<RefreshToken> {
        let filter = doc! {"jti": jti};

        self.collection.find_one(filter).await.ok()?
    }

    async fn find(&self, id: ObjectId) -> Option<RefreshToken> {
        let filter = doc! {"_id": id};

        self.collection.find_one(filter).await.ok()?
    }
}

// db.refresh_tokens.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 })
// pub async fn create_token_hash_index(db: &Database) -> Result<(), mongodb::error::Error> {
//     let options = IndexOptions::builder()
//         .unique(true)
//         // TODO: implement TTL index, for auto removing
//         // use std::time::Duration;
//         // .expire_after(Some(Duration::from_secs(60 * 60))) // 30 minutes
//         .build();
//     let model = IndexModel::builder()
//         .keys(doc! { "tokenHash": 1 })
//         .options(options)
//         .build();
//
//     db.collection::<PasswordResetTokens>("password_reset_token")
//         .create_index(model)
//         .await?;
//
//     Ok(())
// }
//db.collection.createIndex({
//   "userId": 1,
//   "jti": 1,
//   "hash": 1,
//   "valid": 1
// })
