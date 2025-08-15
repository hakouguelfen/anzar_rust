mod common;
mod helpers;
mod test_cases;

use crate::helpers::Helpers;
use common::Common;
use uuid::Uuid;

const X_REFRESH_TOKEN: &str = "x-refresh-token";

#[actix_web::test]
async fn test_logout_success() {
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
        .get(X_REFRESH_TOKEN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let response = client
        .post(format!("{address}/auth/logout"))
        .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_logout_with_invalid_token() {
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
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

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
        "using accessToken instead of refresh_token"
    );

    let response = client
        .post(format!("{address}/auth/logout"))
        .send()
        .await
        .expect("Failed to execute request.");
    assert_eq!(
        401,
        response.status().as_u16(),
        "The API did not fail when the payload was: {}",
        "not sending a refresh_token"
    );
}
