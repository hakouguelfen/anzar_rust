mod shared;
use shared::{Common, Helpers, InvalidTestCases};

use uuid::Uuid;

#[actix_web::test]
async fn test_login_success() {
    let db_name = Uuid::new_v4().to_string();

    // Create User
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&db_name).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_login_failure() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name).await;

    let client = reqwest::Client::new();

    for (invalid_body, error_message) in InvalidTestCases::login_credentials().iter() {
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
