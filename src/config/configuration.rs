use crate::config::DatabaseDriver;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Configuration {
    pub api_url: String,    // Required
    pub database: Database, // Required
    #[serde(default)]
    pub server: Server, // [Optional] Uses Default
    #[serde(default)]
    pub auth: Authentication, // [Optional] Uses Default
    pub security: Security, // Required
}

// Database
// ####################################################
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Database {
    pub driver: DatabaseDriver,
    pub connection_string: String,
}

// Server
// ####################################################
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct Server {
    pub https: HttpsConfig,
    pub cors: CorsConfig,
}
// ------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpsConfig {
    pub enabled: bool,
    pub port: u16,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}
impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 3000,
            cert_path: None,
            key_path: None,
        }
    }
}

// ------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}
impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["localhost:3000".into()],
        }
    }
}

// Authentication
// ####################################################
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct Authentication {
    pub strategy: AuthStrategy,
    pub jwt: JWT,
    pub email: EmailConfig,
    pub password: PasswordConfig,
}

// ------------------------------------------------------------
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum AuthStrategy {
    #[default]
    Session,
    Jwt,
}

// ------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct JWT {
    pub expires_in: i64,
    pub refresh_expires_in: i64,
}
impl Default for JWT {
    fn default() -> Self {
        Self {
            expires_in: 900,
            refresh_expires_in: 604800,
        }
    }
}

// ------------------------------------------------------------
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct EmailConfig {
    pub verification: EmailVerification,
}
// ************************************************************
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct EmailVerification {
    pub required: bool,
    pub token_expires_in: i64, // maybe option
    pub success_redirect: Option<String>,
    pub error_redirect: Option<String>,
}
impl Default for EmailVerification {
    fn default() -> Self {
        Self {
            required: false,
            token_expires_in: 3600,
            success_redirect: None,
            error_redirect: None,
        }
    }
}

// ------------------------------------------------------------
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct PasswordConfig {
    pub requirements: PasswordRequirements,
    pub reset: PasswordReset,
    pub security: PasswordSecurity,
}
// ************************************************************
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct PasswordRequirements {
    pub min_length: u16,
    pub max_length: u16,
}
impl Default for PasswordRequirements {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
        }
    }
}
// ************************************************************
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct PasswordReset {
    pub token_expires_in: i64, // maybe option
    // TODO: remove option and use redirect to root
    pub success_redirect: Option<String>,
    pub error_redirect: Option<String>,
}
impl Default for PasswordReset {
    fn default() -> Self {
        Self {
            token_expires_in: 3600,
            success_redirect: None,
            error_redirect: None,
        }
    }
}
// ************************************************************
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct PasswordSecurity {
    pub max_failed_login_attempts: u8,
    pub lockout_duration: i64,
}
impl Default for PasswordSecurity {
    fn default() -> Self {
        Self {
            max_failed_login_attempts: 5,
            lockout_duration: 1800,
        }
    }
}

// ------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Security {
    pub secret_key: String,
}
