mod shared;

use crate::shared::Helpers;

#[actix_web::test]
async fn test_health_check() {
    // Arrange
    let test_app = Helpers::init_config().await;

    // Act
    let response = test_app
        .client
        .get(format!("{}/health_check", test_app.address))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
}
