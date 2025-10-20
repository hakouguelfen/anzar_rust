mod shared;
use shared::{Helpers, InvalidTestCases};

use anzar::{config::AuthStrategy, extractors::TokenType, scopes::auth::AuthResponse};

#[actix_web::test]
async fn test_jwt_contains_correct_claims() {
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
        let access_token: &str = &tokens.access;
        let refresh_token: &str = &tokens.refresh;

        assert!(!access_token.is_empty() && !refresh_token.is_empty());
        let access_token_claims = Helpers::decode_token(access_token, TokenType::AccessToken);
        let refresh_token_claims = Helpers::decode_token(refresh_token, TokenType::RefreshToken);

        assert!(access_token_claims.is_ok());
        assert!(refresh_token_claims.is_ok());

        assert_eq!(auth_response.user.id, access_token_claims.unwrap().sub);
    }
}

#[actix_web::test]
async fn test_protected_route_with_valid_jwt() {
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
        let access_token: &str = &tokens.access;

        let response = test_app
            .client
            .get(format!("{}/user", test_app.address))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());
    }
}

#[actix_web::test]
async fn test_protected_route_with_invalid_jwt() {
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
        let valid_token: &str = &tokens.access;

        for (token, err_msg, status_code) in InvalidTestCases::jwt_tokens(valid_token) {
            let response = test_app
                .client
                .get(format!("{}/user", test_app.address))
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
}
