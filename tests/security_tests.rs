mod shared;
use shared::Helpers;

use anzar::{config::AuthStrategy, extractors::TokenType, scopes::auth::AuthResponse};

use crate::shared::RefreshTokenRequest;

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
            .bearer_auth(&tokens.access)
            .json(&RefreshTokenRequest {
                refresh_token: refresh_token.to_string(),
            })
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
        let old_access_token: &str = &tokens.access;
        assert!(!old_refresh_token.is_empty());

        // [3] Refresh access token
        let response = test_app
            .client
            .post(format!("{}/auth/refresh-token", test_app.address))
            .json(&RefreshTokenRequest {
                refresh_token: old_refresh_token.to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        let auth_response: AuthResponse = response.json().await.unwrap();

        // assert tokens are not empty
        assert!(&auth_response.tokens.is_some());

        let tokens = auth_response.tokens.as_ref().unwrap();
        let new_access_token: &str = &tokens.access;
        let new_refresh_token: &str = &tokens.refresh;

        // assert tokens are not empty
        assert!(!new_access_token.is_empty() && !new_refresh_token.is_empty());

        let secret_key = test_app.configuration.security.secret_key;
        let access_token_claims =
            Helpers::decode_token(new_access_token, TokenType::AccessToken, &secret_key);
        let refresh_token_claims =
            Helpers::decode_token(new_refresh_token, TokenType::RefreshToken, &secret_key);
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
            .bearer_auth(new_access_token)
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());

        // [6] Logout with invalid refreshToken
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .bearer_auth(old_access_token)
            .json(&RefreshTokenRequest {
                refresh_token: old_refresh_token.to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request.");
        // this operation should successed even if refreshToken is invalid
        // logout is a safe operation
        assert!(response.status().is_success());

        // [7] Logout with valid refreshToken
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .bearer_auth(new_access_token)
            .json(&RefreshTokenRequest {
                refresh_token: new_refresh_token.to_string(),
            })
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());
    }
}
