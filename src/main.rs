use std::net::TcpListener;
use std::sync::LazyLock;

use anzar::config::AppConfig;
use anzar::services::jwt::keys::KEYS;
use anzar::startup;
use anzar::telemetry::{get_subscriber, init_subscriber};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber("anzar".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    LazyLock::force(&KEYS);

    let configuration = AppConfig::from_env().expect("Failed to read configuration");

    let address = format!(
        "{}:{}",
        configuration.server.host, configuration.server.port
    );
    let listener = TcpListener::bind(address)?;

    let server = startup::run(listener)?;
    drop(configuration);
    server.await
}
