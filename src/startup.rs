use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::{http, web, HttpResponse};

use actix_web::{App, HttpServer};
use tracing_actix_web::TracingLogger;

use std::net::TcpListener;

use crate::core::repository::repository_manager::RepositoryManager;
use crate::scopes::{auth, user};

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub fn run(listener: TcpListener, db: mongodb::Database) -> Result<Server, std::io::Error> {
    dotenvy::dotenv().expect("env file not found");

    let repo_manager = web::Data::new(RepositoryManager::new(db));

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
            .wrap(TracingLogger::default())
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
