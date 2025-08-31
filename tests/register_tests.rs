mod shared;
use shared::{Common, Helpers, InvalidTestCases, ValidTestCases};

use uuid::Uuid;

use crate::shared::register_context;

#[actix_web::test]
async fn test_register_success() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let _client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_register_failures() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

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
