use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    options::IndexOptions,
    results::{InsertOneResult, UpdateResult},
    Collection, Database, IndexModel,
};

use super::model::PasswordResetTokens;

pub struct DatabaseOTPRepo {
    collection: Collection<PasswordResetTokens>,
}

impl DatabaseOTPRepo {
    pub fn new(db: &Database) -> Self {
        const COLL_NAME: &str = "password_reset_token";
        DatabaseOTPRepo {
            collection: db.collection::<PasswordResetTokens>(COLL_NAME),
        }
    }
}

pub trait OTPRepo {
    fn insert(
        &self,
        otp: PasswordResetTokens,
    ) -> impl std::future::Future<Output = Result<InsertOneResult, Error>> + Send;
    fn invalidate(
        &self,
        otp_id: ObjectId,
    ) -> impl std::future::Future<Output = Option<PasswordResetTokens>>;
    fn revoke(
        &self,
        user_id: ObjectId,
    ) -> impl std::future::Future<Output = Result<UpdateResult, Error>>;
    fn find(&self, token: String)
        -> impl std::future::Future<Output = Option<PasswordResetTokens>>;
}

impl OTPRepo for DatabaseOTPRepo {
    async fn insert(&self, otp: PasswordResetTokens) -> Result<InsertOneResult, Error> {
        let doc = self.collection.insert_one(otp).await?;
        Ok(doc)
    }

    async fn invalidate(&self, otp_id: ObjectId) -> Option<PasswordResetTokens> {
        let filter = doc! {"_id": otp_id};
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

    async fn find(&self, token_hash: String) -> Option<PasswordResetTokens> {
        let filter = doc! {"tokenHash": token_hash};

        self.collection.find_one(filter).await.ok()?
    }
}

pub async fn create_token_hash_index(db: &Database) -> Result<(), mongodb::error::Error> {
    let options = IndexOptions::builder()
        .unique(true)
        // TODO: implement TTL index, for auto removing
        // use std::time::Duration;
        // .expire_after(Some(Duration::from_secs(60 * 60))) // 30 minutes
        .build();
    let model = IndexModel::builder()
        .keys(doc! { "tokenHash": 1 })
        .options(options)
        .build();

    db.collection::<PasswordResetTokens>("password_reset_token")
        .create_index(model)
        .await?;

    Ok(())
}
