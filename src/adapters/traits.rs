use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::error::Error;

#[async_trait]
pub trait DatabaseAdapter<T: Send + Sync + Serialize + DeserializeOwned + 'static>:
    Send + Sync
{
    async fn insert(&self, data: T) -> Result<String, Error>;
    async fn find_one(&self, filter: Value) -> Option<T>;
    async fn find_one_and_update(&self, filter: Value, update: Value) -> Option<T>;
    async fn update_many(&self, filter: Value, update: Value) -> Result<(), Error>;

    async fn delete_one(&self, filter: Value) -> Result<(), Error>;
    async fn delete_many(&self, filter: Value) -> Result<(), Error>;
}
