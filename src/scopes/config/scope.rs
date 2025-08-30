use actix_web::{
    HttpResponse, Scope,
    web::{self, Json},
};
use serde_json::json;
use uuid::Uuid;

use crate::error::Result;
use crate::scopes::config::models::Configuration;

async fn register_context(ctx: Json<Configuration>) -> Result<HttpResponse> {
    let context_id = Uuid::new_v4().to_string();
    Ok(HttpResponse::Ok().json(json!({"context_id":context_id})))
}

pub fn config_scope() -> Scope {
    web::scope("/configuration/register_context").route("", web::post().to(register_context))
}
