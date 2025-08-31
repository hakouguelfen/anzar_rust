mod shared;
use shared::{Common, Helpers, InvalidTestCases};

use uuid::Uuid;

use crate::shared::register_context;

#[actix_web::test]
async fn test_login_success() {
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let _client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    // Create User
    let response = Helpers::create_user(&address).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&address).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_login_failure() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

    for (body, message, code) in InvalidTestCases::login_credentials().into_iter() {
        // Act
        let response = client
            .post(format!("{address}/auth/login"))
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
