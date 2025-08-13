mod common;
mod helpers;
use common::Common;

mod test_cases;
use test_cases::{InvalidTestCases, ValidTestCases};
use uuid::Uuid;

use crate::helpers::Helpers;

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

    for (invalid_body, error_message) in InvalidTestCases::registration_credentials().iter() {
        // for duplication email test, need to create a valid user before
        if error_message == "duplication emails" {
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
