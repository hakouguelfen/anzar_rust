use actix_session::SessionExt;
use actix_web::{
    Error, HttpMessage,
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};

use crate::extract_service_response;
use crate::{
    config::AuthStrategy,
    extractors::{Claims, TokenType},
    scopes::auth::support,
};
use crate::{
    config::{AppState, Configuration},
    error::InvalidTokenReason,
};

use crate::scopes::auth::service::AuthService;
use crate::services::session::{model::Session, service::SessionServiceTrait};
use crate::{
    error::{Error as AuthError, TokenErrorType},
    services::jwt::JwtDecoderBuilder,
};

fn extract_token_from_header(req: &ServiceRequest, key: String) -> Option<&str> {
    req.headers()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn decode_claims(token: &str, secret_key: &str) -> Result<Claims, AuthError> {
    let decoding_secret = jsonwebtoken::DecodingKey::from_secret(secret_key.as_bytes());
    JwtDecoderBuilder::new(decoding_secret)
        .with_token(token)
        .with_token_type(TokenType::AccessToken)
        .build()
        .map_err(|_| AuthError::InvalidToken {
            token_type: TokenErrorType::AccessToken,
            reason: InvalidTokenReason::SignatureMismatch,
        })
}

async fn find_session(req: &ServiceRequest, token: &str) -> Result<Session, AuthError> {
    let auth_service = extract_auth_service(req)?;
    auth_service.find_session(token).await
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

async fn validate_token(req: &ServiceRequest) -> Result<(), Error> {
    let configuration = extract_configuration_service(req)?;

    match configuration.auth.strategy {
        AuthStrategy::Session => {
            let req_session = req.get_session();
            let data = req_session.get::<String>(support::SESSION_COOKIE)?;

            if let Some(token) = data {
                let session = find_session(req, &token).await?;

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
                update_session_expiray(req, session_id).await?;

                req.extensions_mut().insert::<Session>(session);
            }
        }
        AuthStrategy::Jwt => {
            let secret_key = configuration.security.secret_key;

            let access_token = extract_token_from_header(req, header::AUTHORIZATION.to_string());
            if let Some(token) = access_token {
                let claims = decode_claims(token, &secret_key)?;
                req.extensions_mut().insert::<Claims>(claims.clone());

                let message =
                    format!("successful authentication with user_id:{}", claims.sub).to_string();
                tracing::info!(message);
            }
        }
    };

    Ok(())
}

pub async fn token_validation_middleware(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // pre-processing
    extract_service_response!(req, validate_token(&req).await);
    next.call(req).await
    // post-processing
}
