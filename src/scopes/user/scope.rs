use actix_web::{
    HttpResponse, Scope,
    web::{self},
};

use crate::{
    error::{ErrorResponse, Result},
    extractors::AuthenticatedUser,
    scopes::user::User,
};

#[utoipa::path(
        get,
        path = "/user",
        tag = "Users",
        summary = "Get current User",
        description = "Returns the currently authenticated user's data. Requires a valid Bearer token.",
        security(("bearer_auth" = [])),
        responses(
            (status = 200, description = "User Found", body = User),
            (status = UNAUTHORIZED, description = "invalid request", body = ErrorResponse),
        ),
    )]
#[tracing::instrument(name = "Find user", skip(user))]
async fn find_user(user: AuthenticatedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(user.0))
}

pub fn user_scope() -> Scope {
    web::scope("/user").route("", web::get().to(find_user))
}
