use crate::config::JWT;
use crate::error::{CredentialField, Error, Result};
use crate::scopes::user::User;
use crate::services::jwt::{JwtEncoderBuilder, RefreshToken, Tokens};
use crate::utils::{Token, TokenHasher};
use crate::{extractors::AuthPayload, scopes::auth::service::AuthService};

pub trait JwtServiceTrait {
    fn consume_refresh_token(
        &self,
        payload: AuthPayload,
        user_id: &str,
    ) -> impl Future<Output = Result<()>>;
    fn issue_jwt(
        &self,
        user: &User,
        secret: &[u8],
        jwt_config: JWT,
    ) -> impl std::future::Future<Output = Result<Tokens>>;
    fn invalidate_jwt(&self, jti: &str) -> impl Future<Output = Result<()>>;
    fn invalidate_session(&self, session_id: &str) -> impl Future<Output = Result<()>>;
    fn logout(&self, payload: AuthPayload) -> impl Future<Output = Result<()>>;
    fn logout_all(&self, user_id: &str) -> impl Future<Output = Result<()>>;
    fn find_jwt_by_jti(&self, jti: &str) -> impl Future<Output = Result<RefreshToken>>;
}
impl JwtServiceTrait for AuthService {
    async fn consume_refresh_token(&self, payload: AuthPayload, user_id: &str) -> Result<()> {
        if self.jwt_service.find_and_consume(payload).await.is_err() {
            // TODO: send an email indicating a breach
            self.jwt_service.revoke(user_id).await?;
        }

        Ok(())
    }
    async fn issue_jwt(&self, user: &User, secret: &[u8], jwt_config: JWT) -> Result<Tokens> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let encoding_secret = jsonwebtoken::EncodingKey::from_secret(secret);
        let tokens: Tokens = JwtEncoderBuilder::new(user_id, encoding_secret, &jwt_config)
            .build()
            .inspect_err(|e| {
                tracing::error!("Failed to generate authentication tokens: {:?}", e)
            })?;

        let hashed_refresh_token = Token::hash(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id)
            .with_hash(&hashed_refresh_token)
            .with_jti(&tokens.refresh_token_jti)
            .with_issued_at(chrono::Utc::now())
            .with_expire_at(
                chrono::Utc::now() + chrono::Duration::seconds(jwt_config.refresh_expires_in),
            );

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
