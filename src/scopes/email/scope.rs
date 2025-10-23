use actix_web::{
    HttpResponse, Scope,
    web::{self},
};
use serde::Deserialize;
use validator::Validate;

use crate::{
    error::Result,
    extractors::ConfigurationExtractor,
    scopes::{email::service::EmailVerificationTokenServiceTrait, user::service::UserServiceTrait},
};
use crate::{
    error::{CredentialField, Error},
    extractors::{AuthServiceExtractor, ValidatedQuery},
};

#[derive(Debug, Validate, Deserialize)]
struct TokenQuery {
    pub token: String,
}

#[tracing::instrument(name = "Find user", skip(auth_service, query))]
async fn verify_email(
    AuthServiceExtractor(auth_service): AuthServiceExtractor,
    ConfigurationExtractor(configuration): ConfigurationExtractor,
    ValidatedQuery(query): ValidatedQuery<TokenQuery>,
) -> Result<HttpResponse> {
    let token = query.token;

    let email_verificaiton_token = auth_service
        .validate_email_verification_token(&token)
        .await?;

    let verification_token_id =
        email_verificaiton_token
            .id
            .as_ref()
            .ok_or(Error::MalformedData {
                field: CredentialField::ObjectId,
            })?;

    auth_service
        .invalidate_email_verification_token(verification_token_id)
        .await?;

    auth_service
        .validate_account(&email_verificaiton_token.user_id)
        .await?;

    let success_redirect = match configuration.auth.email.verification.success_redirect {
        Some(url) => url,
        None => configuration.api_url,
    };
    Ok(HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, success_redirect))
        .finish())
}

pub fn email_scope() -> Scope {
    web::scope("/email").route("/verify", web::get().to(verify_email))
}
