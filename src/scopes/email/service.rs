use crate::error::{CredentialField, Error, Result, TokenErrorType};
use crate::scopes::auth::service::AuthService;
use crate::scopes::email::model::EmailVerificationToken;
use crate::utils::{Token, TokenHasher};

pub trait EmailVerificationTokenServiceTrait {
    fn validate_email_verification_token(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<EmailVerificationToken>>;

    fn invalidate_email_verification_token(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<EmailVerificationToken>>;
    fn revoke_email_verification_token(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>>;
    fn insert_email_verification_token(
        &self,
        otp: EmailVerificationToken,
    ) -> impl Future<Output = Result<()>>;
}
impl EmailVerificationTokenServiceTrait for AuthService {
    async fn validate_email_verification_token(
        &self,
        token: &str,
    ) -> Result<EmailVerificationToken> {
        let hash = Token::hash(token);

        // 2. Checks the database for a matching token
        let verification_token = self.email_verification_token_service.find(&hash).await?;
        let verification_token_id = verification_token.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        // 3. Verify token isn't expired or already used
        if !verification_token.valid {
            return Err(Error::TokenAlreadyUsed {
                token_id: verification_token_id.into(),
            });
        }
        if chrono::Utc::now() > verification_token.expires_at {
            self.password_reset_token_service
                .invalidate(verification_token_id)
                .await?;
            return Err(Error::TokenExpired {
                token_type: TokenErrorType::EmailVerificationToken,
                expired_at: verification_token.expires_at,
            });
        }

        Ok(verification_token)
    }

    async fn invalidate_email_verification_token(
        &self,
        id: &str,
    ) -> Result<EmailVerificationToken> {
        self.email_verification_token_service.invalidate(id).await
    }
    async fn revoke_email_verification_token(&self, user_id: &str) -> Result<()> {
        self.email_verification_token_service.revoke(user_id).await
    }
    async fn insert_email_verification_token(&self, otp: EmailVerificationToken) -> Result<()> {
        self.email_verification_token_service.insert(otp).await
    }
}
