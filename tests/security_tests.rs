mod shared;
use shared::{Common, Helpers};

use anzar::{
    core::extractors::TokenType,
    scopes::auth::{AuthResponse, tokens::Tokens},
};
use uuid::Uuid;

use crate::shared::register_context;

const X_REFRESH_TOKEN: &str = "x-refresh-token";
#[actix_web::test]
async fn test_password_not_returned_in_responses() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    // Create User
    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());
    let auth_response = response.json::<AuthResponse>().await;
    assert!(auth_response.is_ok());

    // Login
    let response = Helpers::login(&address).await;
    assert!(response.status().is_success());
    let auth_response = response.json::<AuthResponse>().await;
    assert!(auth_response.is_ok());

    // Login
    let response = Helpers::login(&address).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let refresh_token: &str = &auth_response.refresh_token;

    // Logout
    let response = client
        .post(format!("{address}/auth/logout"))
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
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    // [1] Create User
    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());

    // [2] Login
    let response = Helpers::login(&address).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let refresh_token: &str = &auth_response.refresh_token;
    assert!(!refresh_token.is_empty());

    // [3] Refresh access token
    let response = client
        .post(format!("{address}/auth/refreshToken"))
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

    // [5] Access protected route with valid token
    let response = client
        .get(format!("{address}/user"))
        .bearer_auth(content.access_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    // [6] Logout with invalid refreshToken
    let response = client
        .post(format!("{address}/auth/logout"))
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
        .post(format!("{address}/auth/logout"))
        .header(X_REFRESH_TOKEN, format!("Bearer {}", content.refresh_token))
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());
}
