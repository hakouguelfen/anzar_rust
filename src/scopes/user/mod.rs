use crate::extractors::AuthToken;
use actix_web::{web, HttpResponse, Scope};

pub mod handler;
pub mod models;

async fn find(auth_token: AuthToken) -> HttpResponse {
    HttpResponse::Ok().json(format!("user found {}", auth_token.user_id))
}

pub fn user_scope() -> Scope {
    web::scope("/user").route("/find", web::get().to(find))
}
