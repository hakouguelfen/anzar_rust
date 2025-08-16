#![allow(dead_code)]
use anzar::{
    core::extractors::{Claims, TokenType},
    scopes::auth::tokens::JwtDecoderBuilder,
};
use jsonwebtoken::errors::Error;
use reqwest::Response;

type Result<T> = core::result::Result<T, Error>;

use super::common::Common;
use super::test_cases::ValidTestCases;

pub struct Helpers;
impl Helpers {
    pub async fn login(db_name: &str) -> Response {
        let address = Common::spawn_app(db_name.into()).await;

        let client = reqwest::Client::new();
        let body = ValidTestCases::login_data();
        client
            .post(format!("{address}/auth/login"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user(db_name: &str) -> Response {
        let address = Common::spawn_app(db_name.into()).await;

        let client = reqwest::Client::new();
        let body = ValidTestCases::register_data();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user2(db_name: &str) -> Response {
        let address = Common::spawn_app(db_name.into()).await;

        let client = reqwest::Client::new();
        let body = ValidTestCases::register_data2();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn create_user_with_account_blocked(db_name: &str) -> Response {
        let address = Common::spawn_app(db_name.into()).await;

        let client = reqwest::Client::new();
        let body = ValidTestCases::blocked_account();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub fn decode_token(token: &str, token_type: TokenType) -> Result<Claims> {
        JwtDecoderBuilder::new()
            .with_token(token)
            .with_token_type(token_type)
            .build()
    }
}
