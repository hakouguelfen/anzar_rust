mod shared;
use shared::{Helpers, InvalidTestCases};

use anzar::{config::AuthStrategy, extractors::TokenType, scopes::auth::AuthResponse};

const X_REFRESH_TOKEN: &str = "x-refresh-token";

#[actix_web::test]
async fn test_refresh_token_success() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let refresh_token: &str = &tokens.refresh;
        assert!(!refresh_token.is_empty());
        // refresh access token
        let response = test_app
            .client
            .post(format!("{}/auth/refreshToken", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        let auth_response: AuthResponse = response.json().await.unwrap();
        if let Some(tokens) = &auth_response.tokens {
            let access_token: &str = &tokens.access;
            let refresh_token: &str = &tokens.refresh;

            // assert tokens are not empty
            assert!(!access_token.is_empty() && !refresh_token.is_empty());

            let access_token_claims = Helpers::decode_token(access_token, TokenType::AccessToken);
            let refresh_token_claims =
                Helpers::decode_token(refresh_token, TokenType::RefreshToken);

            // assert new tokens are valid
            assert!(access_token_claims.is_ok());
            assert!(refresh_token_claims.is_ok());

            assert_eq!(
                access_token_claims.unwrap().sub,
                refresh_token_claims.unwrap().sub,
            );
        }
    }
}

#[actix_web::test]
async fn test_refresh_with_invalid_token() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let valid_token: &str = &tokens.refresh;

        for (token, err_msg, status_code) in InvalidTestCases::refresh_tokens(valid_token) {
            let response = test_app
                .client
                .post(format!("{}/auth/refreshToken", test_app.address))
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
}

#[actix_web::test]
async fn test_refresh_token_single_use() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let refresh_token: &str = &tokens.refresh;

        // refresh access token
        let response = test_app
            .client
            .post(format!("{}/auth/refreshToken", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        // refresh access token twice should fail
        let response = test_app
            .client
            .post(format!("{}/auth/refreshToken", test_app.address))
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
}

// Check new tokens are diffrenet from old
// Check new refreshToken hash stored in DB is diffrenet from old one
