use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};
use serde_json::{Value, json};

use crate::scopes::{
    auth::{
        service::{JwtServiceTrait, UserServiceTrait},
        tokens::JwtDecoderBuilder,
    },
    user::User,
};
use crate::startup::AppState;
use crate::{
    core::extractors::{AuthPayload, Claims, TokenType},
    error::Error as AuthError,
};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

fn parse_error(error: AuthError) -> Value {
    json!({"error": error.to_string()})
}

fn extract_token_from_header(req: &ServiceRequest, key: String) -> Option<&str> {
    req.headers()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn decode_claims(token: &str, token_type: TokenType) -> Result<Claims, Error> {
    JwtDecoderBuilder::new()
        .with_token(token)
        .with_token_type(token_type)
        .build()
        .map_err(|_| actix_web::error::ErrorUnauthorized(parse_error(AuthError::InvalidToken)))
}

async fn validate_refresh_token(req: &ServiceRequest, jti: &str) -> Result<(), Error> {
    let auth_service = req
        .app_data::<web::Data<AppState>>()
        .and_then(|state| state.auth_service.lock().ok())
        .and_then(|guard| guard.as_ref().map(|sm| sm.clone()))
        .ok_or(actix_web::error::ErrorInternalServerError(parse_error(
            AuthError::InternalServerError("".into()),
        )))?;

    let refresh_token = auth_service
        .find_jwt_by_jti(jti)
        .await
        .ok_or_else(|| actix_web::error::ErrorUnauthorized(parse_error(AuthError::InvalidToken)))?;

    if !refresh_token.valid {
        return Err(actix_web::error::ErrorUnauthorized(parse_error(
            AuthError::InvalidToken,
        )));
    }

    Ok(())
}

async fn check_user_account(req: &ServiceRequest, user_id: &str) -> Result<(), Error> {
    let auth_service = req
        .app_data::<web::Data<AppState>>()
        .and_then(|state| state.auth_service.lock().ok())
        .and_then(|guard| guard.as_ref().map(|sm| sm.clone()))
        .ok_or(actix_web::error::ErrorInternalServerError(parse_error(
            AuthError::InternalServerError("".into()),
        )))?;

    let user: User = auth_service
        .find_user(user_id.to_string())
        .await
        .map_err(|_| actix_web::error::ErrorNotFound(parse_error(AuthError::UserNotFound)))?;

    if user.account_locked {
        return Err(actix_web::error::ErrorForbidden(parse_error(
            AuthError::AccountSuspended,
        )));
    }

    req.extensions_mut().insert::<User>(user);

    Ok(())
}

pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if [
        "/health_check",
        "/auth/login",
        "/auth/register",
        "/configuration/register_context",
    ]
    .contains(&req.path())
    {
        return next.call(req).await;
    }

    // pre-processing
    let access_token = extract_token_from_header(&req, header::AUTHORIZATION.to_string());
    let refresh_token = extract_token_from_header(&req, X_REFRESH_TOKEN.to_string());

    if let Some(token) = access_token {
        let claims = decode_claims(token, TokenType::AccessToken)?;
        check_user_account(&req, &claims.sub).await?;
        req.extensions_mut().insert::<Claims>(claims);
    }
    if let Some(token) = refresh_token {
        let claims = decode_claims(token, TokenType::RefreshToken)?;
        validate_refresh_token(&req, &claims.jti).await?;

        check_user_account(&req, &claims.sub).await?;
        let payload = AuthPayload::from(claims.sub, token, claims.jti);
        req.extensions_mut().insert::<AuthPayload>(payload);
    }

    // if access_token.is_none() && refresh_token.is_none() {
    //     let err = actix_web::error::ErrorUnauthorized(parse_error(AuthError::InvalidToken));
    //     return Err(err);
    // }

    next.call(req).await
    // post-processing
}
