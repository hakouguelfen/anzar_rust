use mongodb::{Database, IndexModel, bson::doc, options::IndexOptions};

use crate::scopes::{auth::model::PasswordResetToken, user::User};

pub struct MongodbIndexes {
    pub db: Database,
}
impl MongodbIndexes {
    pub async fn create_unique_email_index(&self) -> Result<(), mongodb::error::Error> {
        let options = IndexOptions::builder().unique(true).build();
        let model = IndexModel::builder()
            .keys(doc! { "email": 1 })
            .options(options)
            .build();

        self.db
            .collection::<User>("users")
            .create_index(model)
            .await?;

        Ok(())
    }

    pub async fn create_token_hash_index(&self) -> Result<(), mongodb::error::Error> {
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

        self.db
            .collection::<PasswordResetToken>("password_reset_tokens")
            .create_index(model)
            .await?;

        Ok(())
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
    //     db.collection::<PasswordResetTokens>("password_reset_tokens")
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
}
