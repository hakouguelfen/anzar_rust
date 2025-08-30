use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    api_url: String,
    database: String,
    #[serde(default, rename = "emailAndPassword")]
    email_and_password: EmailAndPassword,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct EmailAndPassword {
    enable: bool,
}

impl Default for EmailAndPassword {
    fn default() -> Self {
        Self { enable: true }
    }
}
