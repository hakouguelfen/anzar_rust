use mongodb::Database;
use std::sync::Arc;

use sqlx::{Pool, Sqlite};

use crate::{
    adapters::{mongodb::MongodbAdapter, sqlite::SQLiteAdapter, traits::DatabaseAdapter},
    scopes::{auth::model::PasswordResetToken, email::model::EmailVerificationToken, user::User},
    services::{jwt::RefreshToken, session::model::Session},
};

const USER: &str = "user";
const REFRESH_TOKEN: &str = "refresh_token";
const PASSWORD_RESET_TOKEN: &str = "password_reset_token";
const EMAIL_VERIFICATION_TOKEN: &str = "email_verification_token";
const SESSION: &str = "session";

pub struct DatabaseAdapters {
    pub user_adapter: Arc<dyn DatabaseAdapter<User>>,
    pub jwt_adapter: Arc<dyn DatabaseAdapter<RefreshToken>>,
    pub session_adapter: Arc<dyn DatabaseAdapter<Session>>,
    pub reset_token_adapter: Arc<dyn DatabaseAdapter<PasswordResetToken>>,
    pub email_verification_token: Arc<dyn DatabaseAdapter<EmailVerificationToken>>,
}

impl DatabaseAdapters {
    pub fn mongodb(db: &Database) -> Self {
        Self {
            user_adapter: Arc::new(MongodbAdapter::<User>::new(db, USER)),
            jwt_adapter: Arc::new(MongodbAdapter::<RefreshToken>::new(db, REFRESH_TOKEN)),
            session_adapter: Arc::new(MongodbAdapter::<Session>::new(db, SESSION)),
            reset_token_adapter: Arc::new(MongodbAdapter::<PasswordResetToken>::new(
                db,
                PASSWORD_RESET_TOKEN,
            )),
            email_verification_token: Arc::new(MongodbAdapter::<EmailVerificationToken>::new(
                db,
                EMAIL_VERIFICATION_TOKEN,
            )),
        }
    }

    pub fn sqlite(db: &Pool<Sqlite>) -> Self {
        Self {
            user_adapter: Arc::new(SQLiteAdapter::<User>::new(db, USER)),
            jwt_adapter: Arc::new(SQLiteAdapter::<RefreshToken>::new(db, REFRESH_TOKEN)),
            session_adapter: Arc::new(SQLiteAdapter::<Session>::new(db, SESSION)),
            reset_token_adapter: Arc::new(SQLiteAdapter::<PasswordResetToken>::new(
                db,
                PASSWORD_RESET_TOKEN,
            )),
            email_verification_token: Arc::new(SQLiteAdapter::<EmailVerificationToken>::new(
                db,
                EMAIL_VERIFICATION_TOKEN,
            )),
        }
    }

    pub fn postgres() -> Self {
        todo!()
    }
}
