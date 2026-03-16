#[derive(Default, Debug, serde::Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl ServerConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
