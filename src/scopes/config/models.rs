use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub api_url: String,
    pub database: String,
    #[serde(default, rename = "emailAndPassword")]
    pub email_and_password: EmailAndPassword,
}
impl Configuration {
    pub fn with_id(mut self, id: String) -> Self {
        self.id = id.into();
        self
    }
    pub fn new(id: String, config: Configuration) -> Self {
        Self {
            id: id.into(),
            ..config
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct EmailAndPassword {
    pub enable: bool,
}

impl Default for EmailAndPassword {
    fn default() -> Self {
        Self { enable: true }
    }
}
