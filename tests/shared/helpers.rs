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

    pub async fn login(test_app: &TestApp) -> Response {
        let body = ValidTestCases::login_data();
        test_app
            .client
            .post(format!("{}/auth/login", test_app.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user(test_app: &TestApp) -> Response {
        let body = ValidTestCases::register_data();
        test_app
            .client
            .post(format!("{}/auth/register", test_app.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn create_user2(test_app: &TestApp) -> Response {
        let body = ValidTestCases::register_data2();
        test_app
            .client
            .post(format!("{}/auth/register", test_app.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn create_user_with_account_blocked(test_app: &TestApp) -> Response {
        let body = ValidTestCases::blocked_account();
        test_app
            .client
            .post(format!("{}/auth/register", test_app.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
    pub async fn get_user(test_app: &TestApp, token: String) -> Response {
        test_app
            .client
            .get(format!("{}/user", test_app.address))
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
