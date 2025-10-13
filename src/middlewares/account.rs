use actix_session::SessionExt;
use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};
use serde_json::{Value, json};

use crate::{config::AppState, error::InvalidTokenReason};
use crate::{
    error::Error as AuthError,
    extractors::{AuthPayload, Claims, TokenType},
    scopes::{
        auth::service::{AuthService, SessionServiceTrait},
        config::{AuthStrategy, Configuration},
    },
    services::session::model::Session,
};
use crate::{
    error::TokenErrorType,
    scopes::{
        auth::service::{JwtServiceTrait, UserServiceTrait},
        user::User,
    },
    services::jwt::JwtDecoderBuilder,
};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

fn parse_error(error: AuthError) -> Value {
    json!({"message": error.to_string()})
}

fn extract_token_from_header(req: &ServiceRequest, key: String) -> Option<&str> {
    req.headers()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn decode_claims(token: &str, token_type: TokenType) -> Result<Claims, Error> {
    JwtDecoderBuilder::default()
        .with_token(token)
        .with_token_type(token_type.clone())
        .build()
        .map_err(|_| {
            actix_web::error::ErrorUnauthorized(parse_error(AuthError::InvalidToken {
                token_type: if token_type == TokenType::AccessToken {
                    TokenErrorType::AccessToken
                } else {
                    TokenErrorType::RefreshToken
                },
                reason: InvalidTokenReason::SignatureMismatch,
            }))
        })
}

async fn validate_refresh_token(req: &ServiceRequest, jti: &str) -> Result<(), Error> {
    let auth_service = extract_auth_service(req)?;

    let refresh_token = auth_service.find_jwt_by_jti(jti).await?;

    if !refresh_token.valid {
        return Err(actix_web::error::ErrorUnauthorized(parse_error(
            AuthError::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: InvalidTokenReason::Expired,
            },
        )));
    }

    Ok(())
}

async fn check_user_account(req: &ServiceRequest, user_id: &str) -> Result<(), Error> {
    let auth_service = extract_auth_service(req)?;

    let user: User = auth_service.find_user(user_id).await.map_err(|_| {
        actix_web::error::ErrorNotFound(parse_error(AuthError::UserNotFound {
            user_id: Some(user_id.into()),
            email: None,
        }))
    })?;

    if user.account_locked {
        return Err(actix_web::error::ErrorForbidden(parse_error(
            AuthError::AccountSuspended {
                user_id: user_id.into(),
            },
        )));
    }

    req.extensions_mut().insert::<User>(user);
    Ok(())
}

async fn find_session(req: &ServiceRequest, session_id: &str) -> Result<Session, Error> {
    let auth_service = extract_auth_service(req)?;

    auth_service
        .find_session(session_id)
        .await
        .map_err(|err| err.into())
}
async fn update_session_expiray(req: &ServiceRequest, session_id: &str) -> Result<Session, Error> {
    let auth_service = extract_auth_service(req)?;

    auth_service.extend_timeout(session_id).await.map_err(|_| {
        actix_web::error::ErrorNotFound(parse_error(AuthError::TokenNotFound {
            token_id: session_id.into(),
        }))
    })
}

fn extract_auth_service(req: &ServiceRequest) -> Result<AuthService, Error> {
    req.app_data::<web::Data<AppState>>()
        .map(|state| state.auth_service.clone())
        .ok_or(actix_web::error::ErrorInternalServerError(parse_error(
            AuthError::InternalServerError("extract auth service".into()),
        )))
}
fn extract_configuration_service(req: &ServiceRequest) -> Result<Configuration, Error> {
    req.app_data::<web::Data<AppState>>()
        .map(|state| state.configuration.clone())
        .ok_or(actix_web::error::ErrorInternalServerError(parse_error(
            AuthError::InternalServerError("extract configuraiton".into()),
        )))
}

pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // pre-processing
    if [
        "/configuration/register_context",
        "/health_check",
        "/auth/register",
        "/auth/login",
    ]
    .contains(&req.path())
    {
        return next.call(req).await;
    }

    let configuration = extract_configuration_service(&req)?;

    match configuration.auth.strategy {
        AuthStrategy::Session => {
            let req_session = req.get_session();
            let data = req_session.get::<String>("SessionID")?;

            if let Some(session_id) = data {
                let session = find_session(&req, &session_id).await?;

                if chrono::Utc::now() > session.expires_at {
                    return Err(actix_web::error::ErrorBadRequest(parse_error(
                        AuthError::TokenExpired {
                            token_type: TokenErrorType::SessionToken,
                            expired_at: session.expires_at,
                        },
                    )));
                }

                // NOTE Only expires after true inactivity period
                let session_id = session.id.as_ref().ok_or(AuthError::MalformedData {
                    field: crate::error::CredentialField::Token,
                })?;
                update_session_expiray(&req, session_id).await?;
                check_user_account(&req, &session.user_id).await?;

                // HACK
                req.extensions_mut()
                    .insert::<AuthPayload>(AuthPayload::default());
                req.extensions_mut().insert::<Session>(session);
            }
        }
        AuthStrategy::Jwt => {
            let access_token = extract_token_from_header(&req, header::AUTHORIZATION.to_string());
            if let Some(token) = access_token {
                let claims = decode_claims(token, TokenType::AccessToken)?;
                check_user_account(&req, &claims.sub).await?;
                req.extensions_mut().insert::<Claims>(claims);
            }

            let refresh_token = extract_token_from_header(&req, X_REFRESH_TOKEN.to_string());
            if let Some(token) = refresh_token {
                let claims = decode_claims(token, TokenType::RefreshToken)?;
                validate_refresh_token(&req, &claims.jti).await?;

                check_user_account(&req, &claims.sub).await?;
                let payload = AuthPayload::from(claims.sub, token, claims.jti);

                // HACK
                req.extensions_mut().insert::<AuthPayload>(payload);
                req.extensions_mut().insert::<Session>(Session::default());
            }
        }
    };

    next.call(req).await
    // post-processing
}
