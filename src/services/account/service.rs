use crate::error::Result;
use crate::scopes::auth::service::AuthService;

use super::model::Account;

pub trait AccountServiceTrait {
    fn find_account(&self, user_id: &str) -> impl Future<Output = Result<Account>>;
    fn update_user_password(&self, id: &str, hash: &str) -> impl Future<Output = Result<Account>>;
    fn unlock_account(&self, id: &str) -> impl Future<Output = Result<Account>>;
}
impl AccountServiceTrait for AuthService {
    async fn find_account(&self, user_id: &str) -> Result<Account> {
        self.account_service.find(user_id).await
    }
    async fn update_user_password(&self, id: &str, hash: &str) -> Result<Account> {
        self.account_service.update_password(id, hash).await
    }
    async fn unlock_account(&self, id: &str) -> Result<Account> {
        self.account_service.unlock_account(id).await
    }
}
