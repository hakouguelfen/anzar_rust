mod shared;
use shared::{Helpers, InvalidTestCases};

use anzar::{extractors::TokenType, scopes::auth::AuthResponse, services::jwt::Tokens};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

#[actix_web::test]
async fn test_refresh_token_success() {
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let refresh_token: &str = &auth_response.refresh_token;
    assert!(!refresh_token.is_empty());

    // refresh access token
    let response = client
        .post(format!("{test_app}/auth/refreshToken"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
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
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user_with_account_blocked(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let valid_token: String = auth_response.refresh_token;

    for (token, err_msg, status_code) in InvalidTestCases::refresh_tokens(valid_token) {
        let response = client
            .post(format!("{test_app}/auth/refreshToken"))
            .header(X_REFRESH_TOKEN, token)
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
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let refresh_token: &str = &auth_response.refresh_token;

    // refresh access token
    let response = client
        .post(format!("{test_app}/auth/refreshToken"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    // refresh access token twice should fail
    let response = client
        .post(format!("{test_app}/auth/refreshToken"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
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
