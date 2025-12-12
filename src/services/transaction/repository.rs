use crate::error::Result;
use crate::services::transaction::adapter::MongodbTransaction;

#[derive(Clone)]
pub struct TransactionRepository {
    adapter: MongodbTransaction,
}

impl TransactionRepository {
    pub fn new(adapter: MongodbTransaction) -> Self {
        Self { adapter }
    }
}

impl TransactionRepository {
    pub async fn start_transactions(&self) -> Result<mongodb::ClientSession> {
        let session = self.adapter.start_transaction().await?;
        Ok(session)
    }
    pub async fn commit_transaction(&self, session: mongodb::ClientSession) -> Result<()> {
        self.adapter.commit_transaction(session).await?;
        Ok(())
    }

    // pub async fn start_transaction<F>(&self, callback: F) -> Result<()>
    // where
    //     //  F: FnOnce(&mut mongodb::ClientSession) -> R + Send + Sync,
    //     // F: for<'s> FnOnce(&'s mut mongodb::ClientSession) -> R + Send + Sync,
    //     // R: Future<Output = Result<()>> + Send,
    //     F: for<'a> FnMut(
    //         &'a mut mongodb::ClientSession,
    //     )
    //         -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>,
    // {
    //     self.adapter.transaction(callback).await?;
    //     Ok(())
    // }
}
