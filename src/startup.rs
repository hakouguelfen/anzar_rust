use actix_cors::Cors;

use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;

use actix_web::dev::Server;
use actix_web::middleware::from_fn;
use actix_web::{http, web};

use actix_web::{App, HttpServer};
use tracing_actix_web::TracingLogger;

use std::net::TcpListener;

use crate::config::AppState;
use crate::middlewares::account::auth_middleware;
use crate::middlewares::rate_limit::RateLimiter;
use crate::scopes::{auth, health, user};

pub async fn run(listener: TcpListener, app_state: AppState) -> Result<Server, std::io::Error> {
    let rate_limitter = web::Data::new(RateLimiter::default());

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

        let session =
            SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
                // FIXME make this true for running https
                // TODO Set appropriate Domain and Path
                .cookie_secure(false)
                .cookie_same_site(actix_web::cookie::SameSite::Strict)
                .cookie_http_only(true)
                .build();

        App::new()
            .wrap(TracingLogger::default())
            .wrap(cors)
            .wrap(from_fn(auth_middleware))
            .wrap(session)
            .app_data(web::Data::new(app_state.clone()))
            .app_data(rate_limitter.clone())
            // .service(config::config_scope())
            .service(auth::auth_scope())
            .service(user::user_scope())
            .service(health::health_scope())
    })
    .listen(listener)?
    .run();

    Ok(server)
}
