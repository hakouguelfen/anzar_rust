use actix_web::{
    HttpResponse, Scope,
    web::{self},
};

use crate::scopes::user::{User, UserResponse};
use crate::{error::Result, extractors::AuthenticatedUser};

#[tracing::instrument(name = "Find user", skip(user))]
async fn find_user(user: AuthenticatedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(<User as Into<UserResponse>>::into(user.0)))
}

pub fn user_scope() -> Scope {
    web::scope("/user").route("", web::get().to(find_user))
}
