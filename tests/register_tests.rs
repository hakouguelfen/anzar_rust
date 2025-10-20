mod shared;
use shared::{Helpers, InvalidTestCases, ValidTestCases};

#[actix_web::test]
async fn test_register_success() {
    let test_app = Helpers::init_config().await;

    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());
}

#[actix_web::test]
async fn test_register_failures() {
    // Arrange
    let test_app = Helpers::init_config().await;

    for (body, message, code) in InvalidTestCases::registration_credentials().into_iter() {
        // for duplication email test, need to create a valid user before
        if message == "duplication emails" {
            let valid_data = ValidTestCases::register_data();
            test_app
                .client
                .post(format!("{}/auth/register", test_app.address))
                .json(&valid_data)
                .send()
                .await
                .expect("Failed to execute request.");
        }

        // Act
        let response = test_app
            .client
            .post(format!("{}/auth/register", test_app.address))
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
