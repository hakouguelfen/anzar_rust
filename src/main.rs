use std::net::TcpListener;

use anzar::{configuration, startup};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let configuration = configuration::get_configuration().expect("Failed to read configuration");

    let address = format!("127.0.0.1:{}", configuration.port);
    let listener = TcpListener::bind(address)?;

    let connection_string = configuration.database.connection_string();
    let client = mongodb::Client::with_uri_str(&connection_string)
        .await
        .expect("Failed to connect to mongodb");
    let db = client.database(&configuration.database.database_name);

    startup::run(listener, db)?.await
}
