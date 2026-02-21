pub mod model;
pub mod service;

mod repository;
mod scope;

pub use repository::EmailVerificationTokenRepository;
pub use scope::{__path_verify_email, email_scope};
