mod shared;
use shared::Helpers;

use anzar::{extractors::TokenType, scopes::auth::AuthResponse};

const X_REFRESH_TOKEN: &str = "x-refresh-token";
#[actix_web::test]
async fn test_password_not_returned_in_responses() {
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

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
    let refresh_token: &str = &auth_response.refresh_token;

    // Logout
    let response = client
        .post(format!("{test_app}/auth/logout"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    let user = response.json::<()>().await;
    assert!(user.is_err());
}

#[actix_web::test]
async fn test_complete_auth_flow() {
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // [1] Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // [2] Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let refresh_token: &str = &auth_response.refresh_token;
    assert!(!refresh_token.is_empty());

    // [3] Refresh access token
    let response = client
        .post(format!("{test_app}/auth/refreshToken"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    // assert tokens are not empty
    assert!(!auth_response.access_token.is_empty() && !auth_response.refresh_token.is_empty());

    let access_token_claims =
        Helpers::decode_token(auth_response.access_token.as_str(), TokenType::AccessToken);
    let refresh_token_claims = Helpers::decode_token(
        auth_response.refresh_token.as_str(),
        TokenType::RefreshToken,
    );
    // assert new tokens are valid
    assert!(access_token_claims.is_ok());
    assert!(refresh_token_claims.is_ok());

    assert_eq!(
        access_token_claims.unwrap().sub,
        refresh_token_claims.unwrap().sub,
    );

    // [5] Access protected route with valid token
    let response = client
        .get(format!("{test_app}/user"))
        .bearer_auth(auth_response.access_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    // [6] Logout with invalid refreshToken
    let response = client
        .post(format!("{test_app}/auth/logout"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
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
    let response = client
        .post(format!("{test_app}/auth/logout"))
        .header(
            X_REFRESH_TOKEN,
            format!("Bearer {}", auth_response.refresh_token),
        )
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());
}
