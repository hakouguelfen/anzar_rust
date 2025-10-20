use crate::error::{CredentialField, Error, Result};
use crate::utils::{Token, TokenHasher};
use crate::{
    scopes::{auth::service::AuthService, user::User},
    services::session::model::Session,
};

// [ SessionTrait ]
pub trait SessionServiceTrait {
    fn issue_session(&self, user_id: &User) -> impl Future<Output = Result<String>>;
    fn find_session(&self, session_id: &str) -> impl Future<Output = Result<Session>>;
    fn extend_timeout(&self, session_id: &str) -> impl Future<Output = Result<Session>>;
}
impl SessionServiceTrait for AuthService {
    async fn issue_session(&self, user: &User) -> Result<String> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        self.session_service.revoke(user_id).await?;

        let token = Token::generate(32);
        let hashed_token = Token::hash(&token);

        let session = Session::default()
            .with_user_id(user_id)
            .with_token(&hashed_token);
        self.session_service.insert(session).await?;

        Ok(token)
    }
    async fn find_session(&self, session_id: &str) -> Result<Session> {
        self.session_service.find(session_id).await
    }
    async fn extend_timeout(&self, session_id: &str) -> Result<Session> {
        self.session_service.extend_timeout(session_id).await
    }
}
