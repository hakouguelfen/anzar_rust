mod common;
mod test_cases;

use common::Common;
use serde::Serialize;
use test_cases::TestCases;

#[derive(Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[actix_web::test]
async fn test_login() {
    // Arrange
    let address = Common::spawn_app().await;

    let client = reqwest::Client::new();
    let body: LoginRequest = LoginRequest {
        email: "hakouguelfen@gmail.com".into(),
        password: "hakouguelfen".into(),
    };

    // Act
    let response = client
        .post(format!("{address}/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_login_failure() {
    // Arrange
    let address = Common::spawn_app().await;

    let client = reqwest::Client::new();

    for (invalid_body, error_message) in TestCases::data().iter() {
        // Act
        let response = client
            .post(format!("{address}/auth/login"))
            .json(&invalid_body)
            .send()
            .await
            .expect("Failed to execute request.");

        // Assert
        assert_eq!(
            401,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            error_message
        );
    }
}
