use actix_web::{http::header, HttpResponse};

use super::tokens::Tokens;
use super::user::User;

const X_REFRESH_TOKEN: &str = "X-Refresh-Token";

pub trait AuthResponseTrait {
    fn load_tokens(tokens: Tokens, user: User) -> Self;
}

impl AuthResponseTrait for HttpResponse {
    fn load_tokens(tokens: Tokens, user: User) -> Self {
        HttpResponse::Ok()
            .append_header((header::ACCESS_CONTROL_EXPOSE_HEADERS, X_REFRESH_TOKEN))
            .append_header((
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                header::AUTHORIZATION.as_str(),
            ))
            .append_header((header::AUTHORIZATION, tokens.access_token))
            .append_header((X_REFRESH_TOKEN, tokens.refresh_token))
            .json(user)
    }
}
