use secrecy::SecretString;

#[derive(serde::Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub jwt_acc_secret: SecretString,
    pub jwt_ref_secret: SecretString,
}

impl ServerConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
