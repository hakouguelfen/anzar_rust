use std::net::TcpListener;
use std::sync::LazyLock;

use anzar::configuration::get_configuration;
use anzar::core::repository::DataBaseRepo;
use anzar::telemetry::{get_subscriber, init_subscriber};
use mongodb::bson::Uuid;

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

pub struct Common;
impl Common {
    pub async fn spawn_app() -> String {
        dotenvy::dotenv().expect("env file not found");
        LazyLock::force(&TRACING);

        let listener = TcpListener::bind("localhost:0").expect("Failed to random port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://localhost:{port}");

        // use test database
        let configuration = get_configuration().expect("Failed to read configuration");
        let connection_string = configuration.database.connection_string();
        let database_name = Uuid::new().to_string();
        let db = DataBaseRepo::new(connection_string, database_name).await;

        let server = anzar::startup::run(listener, db).expect("Failed to bind address");
        let _ = actix_web::rt::spawn(server);

        address
    }
}
