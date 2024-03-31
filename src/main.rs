mod extractors;
mod repository;
mod scopes;
use repository::mongodb_repo::MongoRepo;

use dotenv::dotenv;
use std::env;

use scopes::{auth, user};

use actix_web::{error, web, App, HttpResponse, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let mongorepo = MongoRepo::init().await;
    let db = web::Data::new(mongorepo);
    println!("Server running in http://localhost:8080");

    HttpServer::new(move || {
        let jwt: String = match env::var("JWT_SECRET") {
            Ok(token) => token.to_string(),
            Err(_) => format!("Error loading env variable"),
        };

        let _json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                error::InternalError::from_response(err, HttpResponse::Conflict().finish()).into()
            });

        App::new()
            .app_data(web::Data::new(jwt))
            .app_data(db.clone())
            .service(auth::auth_scope())
            .service(user::user_scope())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
