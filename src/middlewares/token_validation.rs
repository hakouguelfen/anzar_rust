use actix_session::SessionExt;
use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};

use crate::{
    config::AuthStrategy,
    extractors::{AuthPayload, Claims, TokenType},
};
use crate::{
    config::{AppState, Configuration},
    error::InvalidTokenReason,
};

use crate::scopes::auth::service::AuthService;
use crate::services::{
    jwt::service::JwtServiceTrait,
    session::{model::Session, service::SessionServiceTrait},
};
use crate::{
    error::{Error as AuthError, TokenErrorType},
    services::jwt::JwtDecoderBuilder,
};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

fn extract_token_from_header(req: &ServiceRequest, key: String) -> Option<&str> {
    req.headers()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn decode_claims(
    token: &str,
    token_type: TokenType,
    secret_key: &str,
) -> Result<Claims, AuthError> {
    let error_type = match token_type {
        TokenType::AccessToken => TokenErrorType::AccessToken,
        TokenType::RefreshToken => TokenErrorType::RefreshToken,
    };

    let decoding_secret = jsonwebtoken::DecodingKey::from_secret(secret_key.as_bytes());
    JwtDecoderBuilder::new(decoding_secret)
        .with_token(token)
        .with_token_type(token_type.clone())
        .build()
        .map_err(|_| AuthError::InvalidToken {
            token_type: error_type,
            reason: InvalidTokenReason::SignatureMismatch,
        })
}

async fn validate_refresh_token(req: &ServiceRequest, jti: &str) -> Result<(), AuthError> {
    let auth_service = extract_auth_service(req)?;

    let refresh_token = auth_service.find_jwt_by_jti(jti).await?;

    if !refresh_token.valid {
        return Err(AuthError::InvalidToken {
            token_type: TokenErrorType::RefreshToken,
            reason: InvalidTokenReason::Expired,
        });
    }

    Ok(())
}

async fn find_session(req: &ServiceRequest, session_id: &str) -> Result<Session, AuthError> {
    let auth_service = extract_auth_service(req)?;
    auth_service.find_session(session_id).await
}
async fn update_session_expiray(req: &ServiceRequest, id: &str) -> Result<Session, AuthError> {
    let auth_service = extract_auth_service(req)?;
    auth_service.extend_timeout(id).await
}

fn extract_auth_service(req: &ServiceRequest) -> Result<AuthService, AuthError> {
    req.app_data::<web::Data<AppState>>()
        .map(|state| state.auth_service.clone())
        .ok_or(AuthError::InternalServerError(
            "extract auth service".into(),
        ))
}
fn extract_configuration_service(req: &ServiceRequest) -> Result<Configuration, AuthError> {
    req.app_data::<web::Data<AppState>>()
        .map(|state| state.configuration.clone())
        .ok_or(AuthError::InternalServerError(
            "extract configuraiton".into(),
        ))
}

pub async fn token_validation_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // pre-processing
    let configuration = extract_configuration_service(&req)?;

    match configuration.auth.strategy {
        AuthStrategy::Session => {
            let req_session = req.get_session();
            let data = req_session.get::<String>("SessionID")?;

            if let Some(session_id) = data {
                let session = find_session(&req, &session_id).await?;

                if chrono::Utc::now() > session.expires_at {
                    return Err(AuthError::TokenExpired {
                        token_type: TokenErrorType::SessionToken,
                        expired_at: session.expires_at,
                    }
                    .into());
                }

                // NOTE Only expires after true inactivity period
                let session_id = session.id.as_ref().ok_or(AuthError::MalformedData {
                    field: crate::error::CredentialField::Token,
                })?;
                update_session_expiray(&req, session_id).await?;

                req.extensions_mut().insert::<Session>(session);
            }
        }
        AuthStrategy::Jwt => {
            let secret_key = configuration.security.secret_key;
            let access_token = extract_token_from_header(&req, header::AUTHORIZATION.to_string());
            if let Some(token) = access_token {
                let claims = decode_claims(token, TokenType::AccessToken, &secret_key)?;
                req.extensions_mut().insert::<Claims>(claims);
            }

            let refresh_token = extract_token_from_header(&req, X_REFRESH_TOKEN.to_string());
            if let Some(token) = refresh_token {
                let claims = decode_claims(token, TokenType::RefreshToken, &secret_key)?;
                validate_refresh_token(&req, &claims.jti).await?;

                let payload = AuthPayload::from(claims.sub, token, claims.jti);
                req.extensions_mut().insert::<AuthPayload>(payload);
            }
        }
    };

    next.call(req).await
    // post-processing
}
