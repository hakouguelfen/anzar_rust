use mongodb::Database;

use crate::scopes::auth::{DatabaseOTPRepo, DatabaseTokenRepo};
use crate::scopes::user::repository::DatabaseUserRepo;

pub struct RepositoryManager {
    pub user_repo: DatabaseUserRepo,
    pub token_repo: DatabaseTokenRepo,
    pub otp_repo: DatabaseOTPRepo,
}

impl RepositoryManager {
    pub fn new(database: Database) -> Self {
        RepositoryManager {
            user_repo: DatabaseUserRepo::new(&database),
            token_repo: DatabaseTokenRepo::new(&database),
            otp_repo: DatabaseOTPRepo::new(&database),
        }
    }
}
