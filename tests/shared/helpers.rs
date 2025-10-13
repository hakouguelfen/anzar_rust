#![allow(dead_code)]
use anzar::{
    extractors::{Claims, TokenType},
    services::jwt::JwtDecoderBuilder,
};
use reqwest::Response;
use uuid::Uuid;

use crate::shared::TestApp;
use anzar::error::Result;

use super::common::Common;
use super::test_cases::ValidTestCases;

pub struct Helpers;
impl Helpers {
    pub async fn init_config() -> TestApp {
        Common::spawn_app().await.unwrap()
    }

    pub async fn login(address: &TestApp) -> Response {
        let client = reqwest::Client::new();
        let body = ValidTestCases::login_data();
        client
            .post(format!("{address}/auth/login"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user(address: &TestApp) -> Response {
        let client = reqwest::Client::new();
        let body = ValidTestCases::register_data();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user2(address: &TestApp) -> Response {
        let client = reqwest::Client::new();
        let body = ValidTestCases::register_data2();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn create_user_with_account_blocked(address: &TestApp) -> Response {
        let client = reqwest::Client::new();
        let body = ValidTestCases::blocked_account();
        client
            .post(format!("{address}/auth/register"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn get_user(address: &TestApp, token: String) -> Response {
        let client = reqwest::Client::new();
        client
            .get(format!("{address}/user"))
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub fn decode_token(token: &str, token_type: TokenType) -> Result<Claims> {
        JwtDecoderBuilder::default()
            .with_token(token)
            .with_token_type(token_type)
            .build()
    }
}
