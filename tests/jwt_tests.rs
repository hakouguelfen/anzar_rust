mod shared;
use shared::{Common, Helpers, InvalidTestCases};

use anzar::{core::extractors::TokenType, scopes::user::UserResponse};
use uuid::Uuid;

#[actix_web::test]
async fn test_jwt_contains_correct_claims() {
    let db_name = Uuid::new_v4().to_string();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());

    let access_token: &str = response
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let refresh_token: &str = response
        .headers()
        .get("x-refresh-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(!access_token.is_empty() && !refresh_token.is_empty());
    let access_token_claims = Helpers::decode_token(access_token, TokenType::AccessToken);
    let refresh_token_claims = Helpers::decode_token(refresh_token, TokenType::RefreshToken);

    assert!(access_token_claims.is_ok());
    assert!(refresh_token_claims.is_ok());

    let content: UserResponse = response.json().await.unwrap();
    assert_eq!(content.id, access_token_claims.unwrap().sub);
}

#[actix_web::test]
async fn test_protected_route_with_valid_jwt() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());
    let access_token: &str = response
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let response = client
        .get(format!("{address}/user"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_protected_route_with_invalid_jwt() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());

    let valid_token: String = response
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    for (token, err_msg, status_code) in InvalidTestCases::jwt_tokens(valid_token) {
        let response = client
            .get(format!("{address}/user"))
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
