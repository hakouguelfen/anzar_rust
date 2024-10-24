use std::net::TcpListener;

use anzar::core::repository::DataBaseRepo;

use anzar::configuration;
use anzar::startup;
use anzar::telemetry::{get_subscriber, init_subscriber};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let subscriber = get_subscriber("anzar".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    let configuration = configuration::get_configuration().expect("Failed to read configuration");

    let address = format!("127.0.0.1:{}", configuration.port);
    let listener = TcpListener::bind(address)?;

    let connection_string = configuration.database.connection_string();
    let database_name = configuration.database.database_name;
    let db = DataBaseRepo::new(connection_string, database_name).await;

    startup::run(listener, db)?.await
}
