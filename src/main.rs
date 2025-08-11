use std::net::TcpListener;
use std::sync::LazyLock;

use anzar::core::repository::DataBaseRepo;

use anzar::configuration::get_configuration;
use anzar::scopes::auth::keys::KEYS;
use anzar::startup;
use anzar::telemetry::{get_subscriber, init_subscriber};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber("anzar".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    LazyLock::force(&KEYS);

    let configuration = get_configuration().expect("Failed to read configuration");

    let address = format!(
        "{}:{}",
        configuration.application.host, configuration.application.port
    );
    let listener = TcpListener::bind(address)?;

    let connection_string = configuration.database.connection_string();
    let db = DataBaseRepo::start(connection_string).await;

    let server = startup::run(listener, db)?;
    drop(configuration);
    server.await
}
