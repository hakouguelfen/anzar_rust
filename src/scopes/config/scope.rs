use actix_web::{
    HttpResponse, Scope,
    web::{self, Data, Json},
};
use serde_json::json;
use uuid::Uuid;

use crate::scopes::auth::Result;
use crate::scopes::{auth::service::AuthService, config::models::Database};
use crate::{scopes::config::models::Configuration, startup::AppState};

async fn register_context(
    ctx: Json<Configuration>,
    app_state: Data<AppState>,
) -> Result<HttpResponse> {
    let context_id = Uuid::new_v4().to_string();
    let context = ctx.into_inner().with_id(context_id);
    let database = context.database;

    // update_app_config(context.clone());

    _init_db(app_state, database).await?;
    Ok(HttpResponse::Ok().json(json!({"context_id":context.id})))
}

async fn _init_db(app_state: Data<AppState>, database: Database) -> Result<()> {
    // FIXME: Alaways propagate the error whithout changing it in the middle of the road

    let auth_service = AuthService::create(database.db_type, database.connection_string).await?;
    let mut service = app_state.auth_service.lock().unwrap();
    *service = Some(auth_service);

    Ok(())
}

pub fn config_scope() -> Scope {
    web::scope("/configuration/register_context").route("", web::post().to(register_context))
}
