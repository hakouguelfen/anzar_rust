use std::net::TcpListener;
use std::sync::LazyLock;

use anzar::config::AdapterType;
use anzar::config::AppConfig;
use anzar::scopes::config::{Configuration, Database, EmailAndPassword};
use anzar::telemetry::{get_subscriber, init_subscriber};
use derive_more::derive::Display;
use reqwest::Response;

pub static TRACING: LazyLock<()> = LazyLock::new(|| {
    let subscriber_name = "test".into();
    let default_filter_level = "debug".into();

    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

#[derive(Display)]
pub struct TestApp {
    pub address: String,
}

pub struct Common;
impl Common {
    pub async fn spawn_app() -> TestApp {
        LazyLock::force(&TRACING);

        let listener = TcpListener::bind("localhost:0").expect("Failed to random port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://localhost:{port}");

        let server = anzar::startup::run(listener).expect("Failed to bind address");

        actix_web::rt::spawn(server);
        TestApp { address }
    }
}

pub async fn register_context(address: &String, db_name: String) -> Response {
    let client = reqwest::Client::new();

    let mut configuration = AppConfig::from_env().expect("Failed to read configuration");

    if configuration.database.is_nosql() {
        configuration.database.database_name = db_name;
    }

    let connection_string = configuration.database.connection_string();

    let body = Configuration {
        id: None,
        api_url: address.clone(),
        database: Database {
            connection_string,
            db_type: configuration.database.db_type,
        },
        email_and_password: EmailAndPassword { enable: true },
    };

    client
        .post(format!("{address}/configuration/register_context"))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.")
}
