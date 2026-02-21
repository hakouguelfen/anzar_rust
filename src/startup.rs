use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;

use actix_cors::Cors;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

use actix_web::cookie::Key;
use actix_web::dev::Server;
use actix_web::middleware::{self, from_fn};
use actix_web::{App, HttpServer, http, web};

use tracing_actix_web::TracingLogger;

use rustls::{ServerConfig, pki_types::CertificateDer};
use rustls_pemfile::{certs, private_key};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::config::AppState;
use crate::error::{Error, FailureReason};
use crate::middlewares::{account_validation, requests_filters, token_validation};
use crate::scopes::auth::TokenQuery;
use crate::scopes::{auth, email, health, user};

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Anzar Software API",
        version = "0.6.2",
        description = "REST API for the Anzar platform. All protected routes require a Bearer token.",
        contact(name = "Anzar Team", email = "dev@anzar.io"),
        license(name = "GPLV3", identifier="GPL"),
    ),
    paths(
        auth::login,
        auth::register,
        auth::get_session,
        auth::refresh_token,
        auth::logout,
        auth::request_password_reset,
        auth::render_reset_form,
        auth::submit_new_password,
        user::find_user,
        email::verify_email
    ),
    components(
        schemas(TokenQuery)
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Anzar Software", description = "This is a Swagger integration"),
        (name = "Auth", description = "Authentication & session management — login, register, tokens, password reset"),
        (name = "Users", description = "User lookup and profile management"),
        (name = "Email", description = "Email verification flows")
    ),
    external_docs(
        url = "https://anzar_software.gitlab.io/python-sdk/",
        description = "Full Anzar developer documentation"
    ),
)]
pub struct ApiDoc;
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT") // optional, just for docs
                    .build(),
            ),
        );
    }
}

fn load_rustls_config(cert: String, key: String) -> Result<rustls::ServerConfig, Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load certificate chain
    let cert_file = File::open(&cert).map_err(|_| Error::TlsConfig {
        path: cert.clone(),
        reason: FailureReason::NotFound,
    })?;
    let cert_reader = &mut BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer> = certs(cert_reader).collect::<Result<_, _>>()?;
    if cert_chain.is_empty() {
        return Err(Error::TlsConfig {
            path: cert.clone(),
            reason: FailureReason::Empty,
        });
    }

    // Load private key
    let key_file = File::open(&key).map_err(|_| Error::TlsConfig {
        path: key.clone(),
        reason: FailureReason::NotFound,
    })?;
    let key_reader = &mut BufReader::new(key_file);
    let key = private_key(key_reader)?.ok_or_else(|| Error::TlsConfig {
        path: key.clone(),
        reason: FailureReason::NotFound,
    })?;

    // Build TLS config
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| Error::InternalServerError(format!("Failed to build ServerConfig: {}", e)))
}

pub async fn run(listener: TcpListener, app_state: AppState) -> Result<Server, std::io::Error> {
    // FIXME use Arc to remove these multiple cloning
    let app_state_inner = app_state.clone();

    let http_server = HttpServer::new(move || {
        let allowed_origins = app_state.configuration.server.cors.allowed_origins.clone();

        // NOTE maybe implement cors mannually and remove this package
        let allowed_origins_clone = allowed_origins.clone();
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                if let Ok(origin_str) = origin.to_str() {
                    return allowed_origins_clone.contains(&origin_str.to_string());
                }
                false
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                http::header::AUTHORIZATION,
                http::header::ACCEPT,
                http::header::CONTENT_TYPE,
            ])
            .supports_credentials()
            .max_age(3600);

        let key = Key::from(app_state.configuration.security.secret_key.as_bytes());
        let session = SessionMiddleware::builder(CookieSessionStore::default(), key)
            .cookie_secure(true)
            .cookie_same_site(actix_web::cookie::SameSite::Strict)
            .cookie_http_only(true)
            .build();

        // .wrap(TracingLogger::<CustomRootSpanBuilder>::new())
        // .wrap(from_fn(ip_rate_limit_middleware))
        App::new()
            .wrap(TracingLogger::default())
            .wrap(cors)
            .wrap(session)
            .wrap(from_fn(requests_filters))
            .wrap(
                middleware::DefaultHeaders::new()
                    .add((
                        http::header::CONTENT_TYPE,
                        actix_web::mime::APPLICATION_JSON,
                    ))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-XSS-Protection", "0"))
                    .add(("Cache-Control", "no-store"))
                    .add(("Content-Security-Policy", "default-src 'self'"))
                    .add(("Strict-Transport-Security", "max-age=31536000")), // NOTE production only
            )
            .app_data(web::Data::new(app_state_inner.clone()))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(health::health_scope())
            .service(auth::auth_scope())
            .service(
                user::user_scope()
                    .wrap(from_fn(account_validation::account_validation_middleware))
                    .wrap(from_fn(token_validation::token_validation_middleware)),
            )
            .service(email::email_scope())
    });

    let https_cfg = &app_state.configuration.server.https;
    if !https_cfg.enabled {
        tracing::warn!("HTTPS disabled — falling back to HTTP");
        let server = http_server.listen(listener)?.run();
        return Ok(server);
    }

    let server = if let (Some(cert), Some(key)) = (&https_cfg.cert_path, &https_cfg.key_path) {
        let config = load_rustls_config(cert.into(), key.into())?;
        tracing::warn!("HTTPS enabled");
        http_server.listen_rustls_0_23(listener, config)?.run()
    } else {
        tracing::warn!("HTTPS enabled but missing certificate or key — falling back to HTTP");
        http_server.listen(listener)?.run()
    };

    Ok(server)
}
