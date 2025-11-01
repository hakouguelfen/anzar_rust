use crate::error::{CredentialField, Error, Result, TokenErrorType};
use crate::scopes::auth::model::PasswordResetToken;
use crate::scopes::auth::service::AuthService;
use crate::utils::{Token, TokenHasher};

// [ PasswordResetTokenServiceTrait ]
pub trait PasswordResetTokenServiceTrait {
    fn validate_reset_password_token(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<PasswordResetToken>>;

    fn invalidate_password_reset_token(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<PasswordResetToken>>;
    fn revoke_password_reset_token(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>>;
    fn insert_password_reset_token(
        &self,
        otp: PasswordResetToken,
    ) -> impl Future<Output = Result<String>>;
}
impl PasswordResetTokenServiceTrait for AuthService {
    async fn validate_reset_password_token(&self, token: &str) -> Result<PasswordResetToken> {
        let hash = Token::hash(token);
        // FIXME: → Must check hash + expiry + not revoked in one DB transaction.

        // 2. Checks the database for a matching token
        let reset_token = self.password_reset_token_service.find(&hash).await?;
        let reset_token_id = reset_token.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        // 3. Verify token isn't expired or already used
        if !reset_token.valid {
            return Err(Error::TokenAlreadyUsed {
                token_id: reset_token_id.into(),
            });
        }
        if chrono::Utc::now() > reset_token.expires_at {
            self.password_reset_token_service
                .invalidate(reset_token_id)
                .await?;
            return Err(Error::TokenExpired {
                token_type: TokenErrorType::PasswordResetToken,
                expired_at: reset_token.expires_at,
            });
        }

        Ok(reset_token)
    }

    async fn invalidate_password_reset_token(&self, id: &str) -> Result<PasswordResetToken> {
        self.password_reset_token_service.invalidate(id).await
    }
    async fn revoke_password_reset_token(&self, user_id: &str) -> Result<()> {
        self.password_reset_token_service.revoke(user_id).await
    }
    async fn insert_password_reset_token(&self, otp: PasswordResetToken) -> Result<String> {
        self.password_reset_token_service.insert(otp).await
    }
}
