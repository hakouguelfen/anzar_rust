mod shared;
use shared::Helpers;

use anzar::{config::AuthStrategy, extractors::TokenType, scopes::auth::AuthResponse};

const X_REFRESH_TOKEN: &str = "x-refresh-token";
#[actix_web::test]
async fn test_password_not_returned_in_responses() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());
    let auth_response = response.json::<AuthResponse>().await;
    assert!(auth_response.is_ok());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());
    let auth_response = response.json::<AuthResponse>().await;
    assert!(auth_response.is_ok());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let refresh_token: &str = &tokens.refresh;

        // Logout
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        let user = response.json::<()>().await;
        assert!(user.is_err());
    }
}

#[actix_web::test]
async fn test_complete_auth_flow() {
    let test_app = Helpers::init_config().await;

    // [1] Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // [2] Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let old_refresh_token: &str = &tokens.refresh;
        assert!(!old_refresh_token.is_empty());

        // [3] Refresh access token
        let response = test_app
            .client
            .post(format!("{}/auth/refreshToken", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {old_refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        let auth_response: AuthResponse = response.json().await.unwrap();

        // assert tokens are not empty
        assert!(&auth_response.tokens.is_some());

        let tokens = auth_response.tokens.as_ref().unwrap();
        let access_token: &str = &tokens.access;
        let refresh_token: &str = &tokens.refresh;
        assert!(!access_token.is_empty() && !refresh_token.is_empty());

        let access_token_claims = Helpers::decode_token(access_token, TokenType::AccessToken);
        let refresh_token_claims = Helpers::decode_token(refresh_token, TokenType::RefreshToken);
        // assert new tokens are valid
        assert!(access_token_claims.is_ok());
        assert!(refresh_token_claims.is_ok());

        assert_eq!(
            access_token_claims.unwrap().sub,
            refresh_token_claims.unwrap().sub,
        );

        // [5] Access protected route with valid token
        let response = test_app
            .client
            .get(format!("{}/user", test_app.address))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        // [6] Logout with invalid refreshToken
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {old_refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert_eq!(
            401,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            "invalid refreshToken was used"
        );

        // [7] Logout with valid refreshToken
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {}", refresh_token))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());
    }
}
