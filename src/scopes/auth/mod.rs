mod error;
mod extenstion;
mod handler;
mod jwt;
mod models;
mod reset_password;
mod utils;

pub mod email;
pub mod repository;

pub use crate::scopes::user;
pub use error::*;
pub use handler::auth_scope;
pub use jwt::*;
pub use reset_password::{create_token_hash_index, model, DatabaseOTPRepo, OTPRepo};
