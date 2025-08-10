mod models;
mod scope;

// #[cfg(test)]
// mod tests;

pub mod repository;
pub mod service;

pub use models::{Role, User, UserResponse};
pub use repository::create_unique_email_index;
pub use scope::user_scope;
