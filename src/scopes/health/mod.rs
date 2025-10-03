use actix_web::web;
use actix_web::{HttpResponse, Scope};
use serde_json::json;

#[tracing::instrument(name = "Health Check")]
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(json!({ "status": "ok" }))
}

pub fn health_scope() -> Scope {
    web::scope("/health_check").route("", web::get().to(health_check))
}
