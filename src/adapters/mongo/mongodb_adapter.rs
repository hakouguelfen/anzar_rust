use mongodb::{
    Collection, Database,
    bson::Document,
    error::Error,
    options::ReturnDocument,
    results::{InsertOneResult, UpdateResult},
};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, Clone)]
pub struct MongodbAdapter<T: Send + Sync> {
    collection: Collection<T>,
}

impl<T: Send + Sync> MongodbAdapter<T> {
    pub fn new(db: &Database, name: &str) -> Self {
        MongodbAdapter {
            collection: db.collection::<T>(name),
        }
    }
}

pub trait MongodbAdapterTrait<T: Send + Sync> {
    fn insert(
        &self,
        data: T,
    ) -> impl std::future::Future<Output = Result<InsertOneResult, Error>> + Send;
    fn find_one(&self, filter: Document) -> impl std::future::Future<Output = Option<T>>;
    fn find_one_and_update(
        &self,
        filter: Document,
        update: Document,
    ) -> impl std::future::Future<Output = Option<T>>;
    fn update_many(
        &self,
        filter: Document,
        update: Document,
    ) -> impl std::future::Future<Output = Result<UpdateResult, Error>>;
}

impl<T> MongodbAdapterTrait<T> for MongodbAdapter<T>
where
    T: Send + Sync + Serialize + DeserializeOwned,
{
    async fn insert(&self, data: T) -> Result<InsertOneResult, Error> {
        let doc = self.collection.insert_one(data).await?;
        Ok(doc)
    }

    async fn find_one(&self, filter: Document) -> Option<T> {
        self.collection.find_one(filter).await.ok()?
    }

    async fn find_one_and_update(&self, filter: Document, update: Document) -> Option<T> {
        self.collection
            .find_one_and_update(filter, update)
            .return_document(ReturnDocument::After)
            .await
            .ok()?
    }

    async fn update_many(&self, filter: Document, update: Document) -> Result<UpdateResult, Error> {
        let result = self.collection.update_many(filter, update).await?;
        Ok(result)
    }
}
