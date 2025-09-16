use std::fmt::Debug;

use async_trait::async_trait;
use mongodb::{Collection, Database, options::ReturnDocument};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    adapters::traits::{DatabaseAdapter, Document},
    error::Error,
};

#[derive(Debug, Clone)]
pub struct MongodbAdapter<T: Send + Sync + Debug> {
    collection: Collection<T>,
}

impl<T: Send + Sync + Debug> MongodbAdapter<T> {
    pub fn new(db: &Database, name: &str) -> Self {
        MongodbAdapter {
            collection: db.collection::<T>(name),
        }
    }
}

#[async_trait]
impl<T> DatabaseAdapter<T> for MongodbAdapter<T>
where
    T: Debug + Send + Sync + Serialize + DeserializeOwned + 'static,
{
    async fn insert(&self, data: T) -> Result<String, Error> {
        let doc = self
            .collection
            .insert_one(data)
            .await
            .map_err(|_| Error::DatabaseError)?;
        let id = doc.inserted_id.as_object_id().unwrap_or_default();
        Ok(id.to_string())
    }

    async fn find_one(&self, filter: Document) -> Option<T> {
        let mut mongo_filter = mongodb::bson::to_document(&filter).unwrap();
        if let Some(id_value) = mongo_filter.remove("id") {
            mongo_filter.insert("_id", id_value);
        }

        self.collection.find_one(mongo_filter).await.ok()?
    }

    async fn find_one_and_update(&self, filter: Document, update: Document) -> Option<T> {
        let mut mongo_filter = mongodb::bson::to_document(&filter).unwrap();
        let mongo_update = mongodb::bson::to_document(&update).unwrap();

        if let Some(id_value) = mongo_filter.remove("id") {
            mongo_filter.insert("_id", id_value);
        }

        self.collection
            .find_one_and_update(mongo_filter, mongo_update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }

    async fn update_many(&self, filter: Document, update: Document) -> Result<(), Error> {
        let mut mongo_filter = mongodb::bson::to_document(&filter).unwrap();
        let mongo_update = mongodb::bson::to_document(&update).unwrap();

        if let Some(id_value) = mongo_filter.remove("id") {
            mongo_filter.insert("_id", id_value);
        }

        self.collection
            .update_many(mongo_filter, mongo_update)
            .await
            .map_err(|_| Error::DatabaseError)?;

        Ok(())
    }
}
