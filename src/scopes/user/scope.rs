use actix_web::{
    web::{self, Data},
    HttpResponse, Scope,
};
use mongodb::bson::oid::ObjectId;

use crate::core::repository::repository_manager::ServiceManager;
use crate::error::{Error, Result};
use crate::scopes::auth::Claims;

#[tracing::instrument(
    name = "Find user",
    skip(claims, repo),
    fields(user_id = %claims.sub)
)]
async fn find_user(claims: Claims, repo: Data<ServiceManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();

    match repo.user_service.find(user_id).await {
        Ok(user) => Ok(HttpResponse::Ok().json(user.as_response())),
        Err(_) => Err(Error::NotFound),
    }
}

pub fn user_scope() -> Scope {
    web::scope("/user").route("", web::get().to(find_user))
}
