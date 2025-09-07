use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

use crate::scopes::auth::Error;

pub type Document = serde_json::Value;

// pub trait DatabaseAdapter<T: Send + Sync + Serialize + DeserializeOwned> {
//     fn insert(&self, data: T) -> impl Future<Output = Result<String, Error>> + Send;
//     fn find_one(&self, filter: Document) -> impl Future<Output = Option<T>>;
//     fn find_one_and_update(
//         &self,
//         filter: Document,
//         update: Document,
//     ) -> impl Future<Output = Option<T>>;
//     fn update_many(
//         &self,
//         filter: Document,
//         update: Document,
//     ) -> impl Future<Output = Result<(), Error>>;
// }

#[async_trait]
pub trait DatabaseAdapter<T: Send + Sync + Serialize + DeserializeOwned + 'static>:
    Send + Sync
{
    async fn insert(&self, data: T) -> Result<String, Error>;
    async fn find_one(&self, filter: Document) -> Option<T>;
    async fn find_one_and_update(&self, filter: Document, update: Document) -> Option<T>;
    async fn update_many(&self, filter: Document, update: Document) -> Result<(), Error>;
}
