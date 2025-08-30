mod shared;
use shared::{Common, Helpers, InvalidTestCases, ValidTestCases};

use uuid::Uuid;

#[actix_web::test]
async fn test_register_success() {
    let db_name = Uuid::new_v4().to_string();
    let response = Helpers::create_user(&db_name).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_register_failures() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name).await;
    let client = reqwest::Client::new();

    for (body, message, code) in InvalidTestCases::registration_credentials().into_iter() {
        // for duplication email test, need to create a valid user before
        if message == "duplication emails" {
            let valid_data = ValidTestCases::register_data();
            client
                .post(format!("{address}/auth/register"))
                .json(&valid_data)
                .send()
                .await
                .expect("Failed to execute request.");
        }

        // Act
        let response = client
            .post(format!("{address}/auth/register"))
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
