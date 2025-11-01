use crate::error::Result;
use crate::scopes::auth::service::AuthService;

use super::model::Account;

pub trait AccountServiceTrait {
    fn find_account(&self, user_id: &str) -> impl Future<Output = Result<Account>>;
}
impl AccountServiceTrait for AuthService {
    async fn find_account(&self, user_id: &str) -> Result<Account> {
        self.account_service.find(user_id).await
    }
}
