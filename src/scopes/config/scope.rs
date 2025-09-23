use actix_web::{
    HttpResponse, Scope,
    web::{self, Data, Json},
};
use serde_json::json;
use uuid::Uuid;

use crate::error::Result;
use crate::scopes::auth::service::AuthService;
use crate::{scopes::config::models::Configuration, startup::AppState};

async fn register_context(
    ctx: Json<Configuration>,
    app_state: Data<AppState>,
) -> Result<HttpResponse> {
    let context_id = Uuid::new_v4().to_string();
    let configuration = ctx.into_inner().with_id(context_id.clone());

    // update_app_config(context.clone());

    _init_db(app_state, configuration).await?;
    Ok(HttpResponse::Ok().json(json!({"context_id":context_id})))
}

async fn _init_db(app_state: Data<AppState>, configuration: Configuration) -> Result<()> {
    let database = configuration.clone().database;

    let auth_service =
        AuthService::from_database(database.driver, database.connection_string).await?;

    let mut auth_service_mutex = app_state.auth_service.lock().unwrap();
    let mut configuration_mutex = app_state.configuration.lock().unwrap();

    *auth_service_mutex = Some(auth_service);
    *configuration_mutex = Some(configuration);

    Ok(())
}

pub fn config_scope() -> Scope {
    web::scope("/configuration/register_context").route("", web::post().to(register_context))
}
