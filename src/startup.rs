use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::middleware::Logger;
use actix_web::{http, web, HttpResponse};

use actix_web::{App, HttpServer};

use std::net::TcpListener;
use std::sync::Arc;

use crate::core::repository::repository_manager::RepositoryManager;
use crate::scopes::{auth, user};

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub fn run(listener: TcpListener, db: mongodb::Database) -> Result<Server, std::io::Error> {
    let database = Arc::new(db);
    let repo_manager = web::Data::new(RepositoryManager::new(database.clone()));

    let server = HttpServer::new(move || {
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
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(repo_manager.clone())
            .service(auth::auth_scope())
            .service(user::user_scope())
            .route("/health_check", web::get().to(health_check))
    })
    .listen(listener)?
    .run();

    Ok(server)
}
