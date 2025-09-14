mod shared;
use anzar::scopes::{auth::AuthResponse, user::UserResponse};
use shared::Helpers;

use crate::shared::EmailRequest;

#[actix_web::test]
async fn test_inner_behavior() {
    // Arrange
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());
    let auth_response: AuthResponse = response.json().await.unwrap();
    let access_token: &str = &auth_response.access_token;

    // Send forget password request
    let body = EmailRequest {
        email: "hakouguelfen@gmail.com".into(),
    };
    let response = client
        .post(format!("{test_app}/auth/forgot-password"))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");
    assert!(response.status().is_success());

    // Find user by accessToken
    let response = Helpers::get_user(&test_app, access_token.into()).await;
    assert!(response.status().is_success());
    let user: UserResponse = response.json().await.unwrap();

    dbg!(user);
}
