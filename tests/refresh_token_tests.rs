mod common;
mod helpers;
mod test_cases;

use crate::{helpers::Helpers, test_cases::InvalidTestCases};
use anzar::scopes::auth::{TokenType, tokens::Tokens};
use common::Common;
use uuid::Uuid;

#[actix_web::test]
async fn test_refresh_token_success() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());

    let refresh_token: &str = response
        .headers()
        .get("x-refresh-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(!refresh_token.is_empty());

    // refresh access token
    let response = client
        .post(format!("{address}/auth/refreshToken"))
        .bearer_auth(refresh_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    let content: Tokens = response.json().await.unwrap();

    // assert tokens are not empty
    assert!(!content.access_token.is_empty() && !content.refresh_token.is_empty());

    let access_token_claims =
        Helpers::decode_token(content.access_token.as_str(), TokenType::AccessToken);
    let refresh_token_claims =
        Helpers::decode_token(content.refresh_token.as_str(), TokenType::RefreshToken);

    // assert new tokens are valid
    assert!(access_token_claims.is_ok());
    assert!(refresh_token_claims.is_ok());

    assert_eq!(
        access_token_claims.unwrap().sub,
        refresh_token_claims.unwrap().sub,
    );
}

#[actix_web::test]
async fn test_refresh_with_invalid_token() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user_with_account_blocked(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());

    let valid_token: String = response
        .headers()
        .get("x-refresh-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    for (token, err_msg, status_code) in InvalidTestCases::refresh_tokens(valid_token) {
        let response = client
            .post(format!("{address}/auth/refreshToken"))
            .header("authorization", token)
            .send()
            .await
            .expect("Failed to execute request.");

        assert_eq!(
            status_code,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            err_msg
        );
    }
}

#[actix_web::test]
async fn test_refresh_token_single_use() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());

    let refresh_token: &str = response
        .headers()
        .get("x-refresh-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // refresh access token
    let response = client
        .post(format!("{address}/auth/refreshToken"))
        .bearer_auth(refresh_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    // refresh access token twice should fail
    let response = client
        .post(format!("{address}/auth/refreshToken"))
        .bearer_auth(refresh_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert_eq!(
        401,
        response.status().as_u16(),
        "The API did not fail when the payload was: {}",
        "refreshToken was used twice"
    );
}

// Check new tokens are diffrenet from old
// Check new refreshToken hash stored in DB is diffrenet from old one
// change expireAt attribute in accessToken and try to use it
