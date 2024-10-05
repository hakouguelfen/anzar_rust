use actix_web::{
    web::{self, Data},
    HttpResponse, Scope,
};
use mongodb::bson::oid::ObjectId;

use crate::core::repository::repository_manager::RepositoryManager;
use crate::error::{Error, Result};
use crate::scopes::auth::Claims;

use super::repository::UserRepo;

async fn find_user(claims: Claims, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();

    match repo.user_repo.find_by_id(user_id).await {
        Some(user) => Ok(HttpResponse::Ok().json(user.as_response())),
        None => Err(Error::NotFound),
    }
}

async fn activate_account(claims: Claims, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();

    match repo.user_repo.activate_account(user_id).await {
        Some(user) => Ok(HttpResponse::Ok().json(user.as_response())),
        None => Err(Error::BadRequest),
    }
}

pub fn user_scope() -> Scope {
    web::scope("/user")
        .route("/activate-account", web::put().to(activate_account))
        .route("", web::get().to(find_user))
}
