use crate::error::Error;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct MongodbTransaction {
    client: mongodb::Client,
}

impl MongodbTransaction {
    pub fn new(client: &mongodb::Client) -> Self {
        MongodbTransaction {
            client: client.clone(),
        }
    }
}

impl MongodbTransaction {
    pub async fn start_transaction(&self) -> Result<mongodb::ClientSession, Error> {
        let mut session = self.client.start_session().await?;
        session.start_transaction().await?;

        Ok(session)
    }
    pub async fn commit_transaction(
        &self,
        mut session: mongodb::ClientSession,
    ) -> Result<(), Error> {
        session.commit_transaction().await?;
        Ok(())
    }

    // pub async fn transaction<F>(&self, mut callback: F) -> Result<(), Error>
    // where
    //     // F: for<'s> FnOnce(&'s mut mongodb::ClientSession) -> R + Send + Sync,
    //     // R: Future<Output = Result<(), Error>> + Send,
    //     F: for<'a> FnMut(
    //         &'a mut mongodb::ClientSession,
    //     ) -> std::pin::Pin<
    //         Box<dyn Future<Output = Result<(), Error>> + Send + 'static>,
    //     >,
    // {
    //     let mut session = self.client.start_session().await?;
    //     callback(&mut session).await?;
    //     session.commit_transaction().await?;
    //
    //     Ok(())
    // }
}
