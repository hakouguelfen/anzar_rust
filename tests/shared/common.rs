use std::fs::File;
use std::io::Write;
use std::net::TcpListener;
use std::sync::LazyLock;

use anzar::adapters::sqlite::SQLite;
use anzar::config::AppState;
use anzar::config::DatabaseDriver;
use anzar::config::EnvironmentConfig;
use anzar::scopes::auth::service::AuthService;

use anzar::config::{AuthStrategy, Authentication, Configuration, Database};

use anzar::telemetry::{get_subscriber, init_subscriber};
use derive_more::derive::Display;
use reqwest::Response;

pub static TRACING: LazyLock<()> = LazyLock::new(|| {
    let subscriber_name = "test";
    let default_filter_level = "debug".into();

    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

pub struct TestApp {
    pub address: String,
    pub client: reqwest::Client,
    pub configuration: Configuration,
}

pub struct Common;
impl Common {
    pub async fn spawn_app() -> Result<TestApp, std::io::Error> {
        LazyLock::force(&TRACING);

        let listener = TcpListener::bind("localhost:0").expect("Failed to random port");
        let port = listener.local_addr()?.port();
        let address = format!("http://localhost:{port}");

        let app_state = AppState::test(&address).await?;
        let server = anzar::startup::run(listener, app_state.clone())
            .await
            .expect("Failed to bind address");

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        actix_web::rt::spawn(server);
        Ok(TestApp {
            address,
            client,
            configuration: app_state.configuration,
        })
    }
}
