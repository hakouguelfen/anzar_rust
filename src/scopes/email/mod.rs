pub mod model;
pub mod service;

mod repository;
mod scope;

pub use repository::EmailVerificationTokenRepository;
pub use scope::email_scope;
