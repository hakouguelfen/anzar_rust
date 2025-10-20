use crate::error::{CredentialField, Error, InvalidTokenReason, Result, TokenErrorType};
use crate::scopes::user::User;
use crate::services::jwt::{JwtEncoderBuilder, RefreshToken, Tokens};
use crate::utils::{Token, TokenHasher};
use crate::{extractors::AuthPayload, scopes::auth::service::AuthService};

// [ JwtServiceTrait ]
pub trait JwtServiceTrait {
    fn validate_jwt(&self, payload: AuthPayload, user_id: &str)
    -> impl Future<Output = Result<()>>;
    fn issue_jwt(&self, user: &User) -> impl std::future::Future<Output = Result<Tokens>>;
    fn invalidate_jwt(&self, jti: &str) -> impl Future<Output = Result<()>>;
    fn invalidate_session(&self, session_id: &str) -> impl Future<Output = Result<()>>;
    fn logout(&self, payload: AuthPayload) -> impl Future<Output = Result<()>>;
    fn logout_all(&self, user_id: &str) -> impl Future<Output = Result<()>>;
    fn find_jwt_by_jti(&self, jti: &str) -> impl Future<Output = Result<RefreshToken>>;
}
impl JwtServiceTrait for AuthService {
    async fn validate_jwt(&self, payload: AuthPayload, user_id: &str) -> Result<()> {
        if self.jwt_service.find(payload).await.is_none() {
            tracing::error!("Invalid refresh token detected for user: {}", user_id);

            // TODO: send an email indicating a breach
            // revoke or invalidate one token ?
            // maybe a user decided to revoke access to one of his devices
            // then he tried to use that devices, token is revoked but trying to validate it
            // will fail then self.jwt_service.revoke(user_id).await? will be excuted
            // [NOT RECOMMENDED]
            self.jwt_service.revoke(user_id).await?;
            return Err(Error::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: InvalidTokenReason::NotFound,
            });
        }

        Ok(())
    }
    async fn issue_jwt(&self, user: &User) -> Result<Tokens> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let tokens: Tokens = JwtEncoderBuilder::new(user_id).build().inspect_err(|e| {
            tracing::error!("Failed to generate authentication tokens: {:?}", e)
        })?;

        let hashed_refresh_token = Token::hash(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id)
            .with_hash(&hashed_refresh_token)
            .with_jti(&tokens.refresh_token_jti)
            .with_issued_at(chrono::Utc::now())
            .with_expire_at(chrono::Utc::now() + chrono::Duration::days(30));

        self.jwt_service.insert(refresh_token).await?;

        Ok(tokens)
    }

    async fn invalidate_jwt(&self, jti: &str) -> Result<()> {
        self.jwt_service.invalidate(jti).await?;
        Ok(())
    }
    async fn invalidate_session(&self, token: &str) -> Result<()> {
        self.session_service.invalidate(token).await?;
        Ok(())
    }

    async fn logout(&self, payload: AuthPayload) -> Result<()> {
        self.jwt_service.invalidate(&payload.jti).await?;
        self.session_service.revoke(&payload.user_id).await?;
        Ok(())
    }
    async fn logout_all(&self, user_id: &str) -> Result<()> {
        self.jwt_service.revoke(user_id).await?;
        self.session_service.revoke(user_id).await?;
        Ok(())
    }

    async fn find_jwt_by_jti(&self, jti: &str) -> Result<RefreshToken> {
        self.jwt_service.find_by_jti(jti).await
    }
}
