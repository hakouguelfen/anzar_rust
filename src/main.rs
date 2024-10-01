mod core;
mod error;
mod scopes;

use actix_cors::Cors;
use actix_web::{http, web};

use actix_web::{App, HttpServer};

use dotenv::dotenv;

use core::repository::{repository_manager::RepositoryManager, DataBaseRepo};
use scopes::*;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    dotenv().ok();
    const PORT: u16 = 3000;

    let db_repo = DataBaseRepo::default().await;
    let database = Arc::new(db_repo);

    let repo_manager = web::Data::new(RepositoryManager::new(database.clone()));

    log::info!("Server running at port {PORT}");
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                http::header::AUTHORIZATION,
                http::header::ACCEPT,
                http::header::CONTENT_TYPE,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(repo_manager.clone())
            .service(auth::auth_scope())
            .service(user::user_scope())
    })
    .bind(("0.0.0.0", PORT))?
    .run()
    .await
}
