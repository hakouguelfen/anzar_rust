use actix_web::{web, HttpResponse, Scope};
use mongodb::{bson::doc, Database};
use serde::Deserialize;

use crate::extractors::AuthToken;

use super::user::models::User;

// mod error;
mod handler;
mod jwt;

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

async fn login(
    secret: web::Data<String>,
    req: web::Json<LoginRequest>,
    db: web::Data<Database>,
) -> HttpResponse {
    match handler::login(db, req.into_inner(), secret.to_string()).await {
        Ok((user, tokens)) => HttpResponse::Ok()
            .append_header(("Authorization", tokens.access_token))
            .append_header(("X-Refresh-Token", tokens.refresh_token))
            .json(user),
        Err(err) => err,
    }
}

async fn register(
    secret: web::Data<String>,
    req: web::Json<User>,
    db: web::Data<Database>,
) -> HttpResponse {
    match handler::register(db, req.into_inner(), secret.to_string()).await {
        Ok((user, tokens)) => HttpResponse::Ok()
            .append_header(("Authorization", tokens.access_token))
            .append_header(("X-Refresh-Token", tokens.refresh_token))
            .json(user),
        Err(err) => err,
    }
}

async fn refresh_user_token(
    auth_token: AuthToken,
    secret: web::Data<String>,
    db: web::Data<Database>,
) -> HttpResponse {
    match handler::refresh_user_token(auth_token, db, secret.to_string()).await {
        Ok(tokens) => HttpResponse::Ok().json(tokens),
        Err(err) => err,
    }
}

async fn logout() -> HttpResponse {
    // findUserById and replase refreshToken -> Null
    todo!()
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/refreshToken", web::post().to(refresh_user_token))
        .route("/logout", web::post().to(logout))
}
