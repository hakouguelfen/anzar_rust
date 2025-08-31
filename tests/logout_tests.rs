mod shared;
use anzar::scopes::auth::AuthResponse;
use shared::{Common, Helpers};

use uuid::Uuid;

use crate::shared::register_context;

const X_REFRESH_TOKEN: &str = "x-refresh-token";

#[actix_web::test]
async fn test_logout_success() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    // Create User
    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());

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
    dbg!(&response);
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_logout_with_invalid_token() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    // Create User
    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&address).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();
    let access_token: &str = &auth_response.access_token;

    let response = client
        .post(format!("{address}/auth/logout"))
        .header(X_REFRESH_TOKEN, format!("Bearer {access_token}"))
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
