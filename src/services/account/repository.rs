use std::sync::Arc;

use serde_json::json;

use crate::error::{Error, Result, TokenErrorType};
use crate::utils::parser::Parser;
use crate::{adapters::DatabaseAdapter, config::DatabaseDriver};

use super::model::Account;

#[derive(Clone)]
pub struct AccountRepository {
    adapter: Arc<dyn DatabaseAdapter<Account>>,
    database_driver: DatabaseDriver,
}

impl AccountRepository {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<Account>>,
        database_driver: DatabaseDriver,
    ) -> Self {
        Self {
            adapter,
            database_driver,
        }
    }
}

impl AccountRepository {
    pub async fn insert(&self, account: Account) -> Result<()> {
        self.adapter.insert(account).await.map_err(|e| {
            tracing::error!("Failed to insert Account to database: {:?}", e);
            Error::TokenCreationFailed {
                token_type: TokenErrorType::SessionToken,
            }
        })?;

        Ok(())
    }

    pub async fn find(&self, user_id: &str) -> Result<Account> {
        let filter = json! ({"userId": user_id});
        let filter = Parser::mode(self.database_driver).convert(filter);

        match self.adapter.find_one(filter).await {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(Error::UserNotFound {
                user_id: Some(user_id.into()),
                email: None,
            }),
            Err(err) => Err(err),
        }
    }

    pub async fn update_password(&self, user_id: &str, password: &str) -> Result<Account> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));
        let update = json!({ "$set": json!({"password": password}) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(account)) => Ok(account),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn lock_account(&self, user_id: &str) -> Result<Account> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));
        let update = json!( {
            "$set": json!({
                "locked": true
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(account)) => Ok(account),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }
    pub async fn unlock_account(&self, user_id: &str) -> Result<Account> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));
        let update = json!( {
            "$set": json!({
                "locked": false
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(account)) => Ok(account),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }
}
