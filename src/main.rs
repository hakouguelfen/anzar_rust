use std::net::TcpListener;

use anzar::config::{AppState, EnvironmentConfig};
use anzar::startup;
use anzar::telemetry::{get_subscriber, init_subscriber};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // FIXME allow users to send emails, make some callbacks in you SDK
    let env_config = EnvironmentConfig::from_env().expect("Failed to read configuration");

    let subscriber = get_subscriber(&env_config.name, "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    let address = format!("{}:{}", env_config.server.host, env_config.server.port);
    let listener = TcpListener::bind(address)?;

    let app_state = AppState::prod(&env_config).await?;
    dbg!(&app_state.configuration);
    let server = startup::run(listener, app_state).await?;

    drop(env_config);
    server.await
}
