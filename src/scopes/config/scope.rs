use actix_web::{
    HttpResponse, Scope,
    web::{self, Data, Json},
};
use serde_json::json;
use uuid::Uuid;

use crate::{error::Result, parser::AdapterType, scopes::auth::service::AuthService};
use crate::{scopes::config::models::Configuration, startup::AppState};

async fn register_context(
    ctx: Json<Configuration>,
    app_state: Data<AppState>,
) -> Result<HttpResponse> {
    let context_id = Uuid::new_v4().to_string();
    let context = ctx.into_inner().with_id(context_id);
    let connection_string = context.database;

    // update_app_config(context.clone());
    _init_db(app_state, connection_string).await;

    Ok(HttpResponse::Ok().json(json!({"context_id":context.id})))
}

async fn _init_db(app_state: Data<AppState>, connection_string: String) {
    // FIXME
    // Alaways propagate the error whithout changin it in the middle of the road
    // let connection_string = "sqlite::memory:".to_string();
    // let connection_string = "anzar.db".to_string();

    let adapter_type = AdapterType::Sqlite;
    let auth_service = AuthService::create(adapter_type, connection_string).await;
    let mut service = app_state.auth_service.lock().unwrap();
    *service = Some(auth_service);
}

pub fn config_scope() -> Scope {
    web::scope("/configuration/register_context").route("", web::post().to(register_context))
}
