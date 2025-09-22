use actix_web::{
    HttpResponse, Scope,
    web::{self},
};

#[tracing::instrument(name = "Health Check")]
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub fn health_scope() -> Scope {
    web::scope("/health_check").route("", web::get().to(health_check))
}
