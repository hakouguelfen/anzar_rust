use mongodb::Database;

use crate::scopes::auth::JWTService;
use crate::scopes::auth::{PasswordResetTokenService, service::AuthService};
use crate::scopes::user::service::UserService;

pub struct ServiceManager {
    pub auth_service: AuthService,
    pub user_service: UserService,
    pub password_reset_token_service: PasswordResetTokenService,
    pub jwt_service: JWTService,
}

impl ServiceManager {
    pub fn new(database: Database) -> Self {
        ServiceManager {
            auth_service: AuthService::new(&database),
            user_service: UserService::new(&database),
            password_reset_token_service: PasswordResetTokenService::new(&database),
            jwt_service: JWTService::new(&database),
        }
    }
}
