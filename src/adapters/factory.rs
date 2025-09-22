use mongodb::Database;
use std::sync::Arc;

use sqlx::{Pool, Sqlite};

use crate::{
    adapters::{mongodb::MongodbAdapter, sqlite::SQLiteAdapter, traits::DatabaseAdapter},
    scopes::{auth::model::PasswordResetToken, user::User},
    services::{jwt::RefreshToken, session::model::Session},
};

// Table names use plural forms (users, refresh_tokens)
const USER: &str = "users";
const REFRESH_TOKEN: &str = "refresh_tokens";
const PASSWORD_RESET_TOKEN: &str = "password_reset_tokens";
const SESSION: &str = "sessions";

pub struct DatabaseAdapters {
    pub user_adapter: Arc<dyn DatabaseAdapter<User>>,
    pub jwt_adapter: Arc<dyn DatabaseAdapter<RefreshToken>>,
    pub session_adapter: Arc<dyn DatabaseAdapter<Session>>,
    pub reset_token_adapter: Arc<dyn DatabaseAdapter<PasswordResetToken>>,
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
        }
    }

    pub fn postgres() -> Self {
        todo!()
    }
}
