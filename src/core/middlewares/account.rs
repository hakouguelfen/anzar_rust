use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};
use mongodb::bson::oid::ObjectId;

use crate::core::extractors::{Claims, TokenType};
use crate::core::repository::repository_manager::ServiceManager;
use crate::scopes::{auth::tokens::JwtDecoderBuilder, user::User};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

fn decode_claims(token: &str, token_type: TokenType) -> Result<Claims, Error> {
    JwtDecoderBuilder::new()
        .with_token(token)
        .with_token_type(token_type)
        .build()
        .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))
}

async fn check_user_account(req: &ServiceRequest, user_id: &str) -> Result<(), Error> {
    let repo_manager = req.app_data::<web::Data<ServiceManager>>().ok_or_else(|| {
        actix_web::error::ErrorInternalServerError("Service manager is not available")
    })?;

    let user_id: ObjectId = ObjectId::parse_str(user_id).unwrap_or_default();
    let user: User = repo_manager
        .user_service
        .find(user_id)
        .await
        .map_err(|_| actix_web::error::ErrorNotFound("No User Found"))?;

    if user.account_locked {
        return Err(actix_web::error::ErrorForbidden("Account is blocked"));
    }

    req.extensions_mut().insert::<User>(user);

    Ok(())
}

pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // pre-processing
    let access_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let refresh_token = req
        .headers()
        .get(X_REFRESH_TOKEN)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if let Some(token) = access_token {
        let claims = decode_claims(token, TokenType::AccessToken)?;
        check_user_account(&req, &claims.sub).await?;
    }
    if let Some(token) = refresh_token {
        let claims = decode_claims(token, TokenType::RefreshToken)?;
        check_user_account(&req, &claims.sub).await?;
    }

    next.call(req).await
    // post-processing
}
