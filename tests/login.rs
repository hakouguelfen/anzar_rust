mod common;
mod test_cases;

use common::Common;
use test_cases::TestCases;

#[actix_web::test]
async fn test_login_before_register() {
    // Arrange
    let address = Common::spawn_app().await;

    let client = reqwest::Client::new();
    let body = TestCases::login_data();

    // Act
    let response = client
        .post(format!("{address}/auth/login"))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_client_error());
}

#[actix_web::test]
async fn test_register_and_login() {
    // Arrange
    let address = Common::spawn_app().await;

    let client = reqwest::Client::new();
    let body = TestCases::register_data();

    // Act
    let response = client
        .post(format!("{address}/auth/register"))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());

    // Act
    let body = TestCases::login_data();
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
