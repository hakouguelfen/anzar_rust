use serde::{Deserialize, Serialize};

use crate::config::DatabaseDriver;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct EmailAndPassword {
    pub enable: bool,
}

impl Default for EmailAndPassword {
    fn default() -> Self {
        Self { enable: true }
    }
}

#[derive(Debug, Default, Clone, Copy, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub enum AuthStrategy {
    #[default]
    Session,
    Jwt,
}
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct Authentication {
    pub strategy: AuthStrategy,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Database {
    pub connection_string: String,
    pub driver: DatabaseDriver,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Configuration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub api_url: String,
    pub database: Database,
    pub auth: Authentication,
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
