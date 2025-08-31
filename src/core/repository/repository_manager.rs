use crate::adapters::mongo::MongoDB;
use crate::scopes::auth::JWTService;
use crate::scopes::auth::{PasswordResetTokenService, service::AuthService};
use crate::scopes::user::service::UserService;

#[derive(Debug, Clone)]
pub struct ServiceManager {
    pub auth_service: AuthService,
    pub user_service: UserService,
    pub password_reset_token_service: PasswordResetTokenService,
    pub jwt_service: JWTService,
}

impl ServiceManager {
    pub async fn new(connection_string: String) -> Self {
        let database = MongoDB::start(connection_string).await;

        ServiceManager {
            auth_service: AuthService::new(&database),
            user_service: UserService::new(&database),
            password_reset_token_service: PasswordResetTokenService::new(&database),
            jwt_service: JWTService::new(&database),
        }
    }
}
