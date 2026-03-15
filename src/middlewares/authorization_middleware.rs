use actix_web::{
    Error, HttpMessage, ResponseError,
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web,
};

use crate::{
    config::{AppState, Configuration},
    error::InvalidTokenReason,
    extract_service_response,
};
use crate::{
    error::{Error as AuthError, TokenErrorType},
    services::account::service::AccountServiceTrait,
};

use crate::scopes::{
    auth::service::AuthService,
    user::{User, service::UserServiceTrait},
};
use crate::{extractors::Claims, services::session::model::Session};

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

async fn validate_user(req: &ServiceRequest, user_id: &str) -> Result<User, AuthError> {
    let auth_service = extract_auth_service(req)?;

    let user: User = auth_service.find_user(user_id).await?;
    let account = auth_service.find_account(user_id).await?;

    if account.locked {
        return Err(AuthError::AccountSuspended {});
    }

    Ok(user)
}

fn extract_user_id_from_extensions(req: &ServiceRequest) -> Result<String, AuthError> {
    let configuration = extract_configuration_service(req)?;

    match configuration.auth.strategy {
        crate::config::AuthStrategy::Session => {
            if let Some(session) = req.extensions().get::<Session>() {
                return Ok(session.user_id.clone());
            }

            Err(AuthError::InvalidToken {
                token_type: TokenErrorType::SessionToken,
                reason: InvalidTokenReason::NotFound,
            })
        }
        crate::config::AuthStrategy::Jwt => {
            if let Some(claims) = req.extensions().get::<Claims>() {
                return Ok(claims.sub.clone());
            }

            Err(AuthError::InvalidToken {
                token_type: TokenErrorType::AccessToken,
                reason: InvalidTokenReason::NotFound,
            })
        }
    }
}

pub async fn authorization_middleware(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // pre-processing
    let user_id = extract_service_response!(req, extract_user_id_from_extensions(&req));
    let user = extract_service_response!(req, validate_user(&req, &user_id).await);

    req.extensions_mut().insert::<User>(user);
    next.call(req).await
    // post-processing
}
