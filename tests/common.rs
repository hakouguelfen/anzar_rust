use std::net::TcpListener;

use anzar::configuration;

pub struct Common;
impl Common {
    pub async fn spawn_app() -> String {
        dotenvy::dotenv().expect("env file not found");

        let listener = TcpListener::bind("localhost:0").expect("Failed to random port");
        let port = listener.local_addr().unwrap().port();

        let configuration =
            configuration::get_configuration().expect("Failed to read configuration");
        let connection_string = configuration.database.connection_string();

        let client = mongodb::Client::with_uri_str(&connection_string)
            .await
            .expect("Failed to connect to mongodb");
        let db = client.database(&configuration.database.database_name);

        let server = anzar::startup::run(listener, db).expect("Failed to bind address");
        let _ = actix_web::rt::spawn(server);

        format!("http://localhost:{port}")
    }
}
