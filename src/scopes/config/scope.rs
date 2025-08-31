use actix_web::{
    HttpResponse, Scope,
    web::{self, Json},
};
use serde_json::json;
use uuid::Uuid;

use crate::scopes::config::models::Configuration;
use crate::{configuration::update_app_config, error::Result};

async fn register_context(ctx: Json<Configuration>) -> Result<HttpResponse> {
    let context_id = Uuid::new_v4().to_string();
    let context = ctx.into_inner().with_id(context_id);

    update_app_config(context.clone());

    Ok(HttpResponse::Ok().json(json!({"context_id":context.id})))
}

pub fn config_scope() -> Scope {
    web::scope("/configuration/register_context").route("", web::post().to(register_context))
}
