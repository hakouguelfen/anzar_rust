use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;

use tracing_actix_web::TracingLogger;

use actix_cors::Cors;
use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::cookie::Key;
use actix_web::dev::Server;
use actix_web::middleware::from_fn;
use actix_web::{App, HttpServer};
use actix_web::{http, web};

use rustls::{ServerConfig, pki_types::CertificateDer};
use rustls_pemfile::{certs, private_key};

use crate::config::AppState;
use crate::error::{Error, FailureReason};
use crate::middlewares::account_validation;
use crate::middlewares::rate_limiting::ip_rate_limit_middleware;
use crate::middlewares::token_validation;
use crate::scopes::{auth, email, health, user};

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

        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _req_head| {
                allowed_origins
                    .contains(&origin.to_str().unwrap().to_string())
                    .to_owned()
            })
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
                // FIXME Set appropriate Domain and Path
                .cookie_secure(true)
                .cookie_same_site(actix_web::cookie::SameSite::Strict)
                .cookie_http_only(true)
                .build();

        App::new()
            .wrap(TracingLogger::default())
            .wrap(cors)
            .wrap(session)
            .wrap(from_fn(ip_rate_limit_middleware))
            .app_data(web::Data::new(app_state_inner.clone()))
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
