mod shared;
use shared::{Helpers, InvalidTestCases};

#[actix_web::test]
async fn test_login_success() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_login_failure() {
    // Arrange
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    for (body, message, code) in InvalidTestCases::login_credentials().into_iter() {
        // Act
        let response = client
            .post(format!("{test_app}/auth/login"))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.");

        // Assert
        assert_eq!(
            code,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            message
        );
    }
}
