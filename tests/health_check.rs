mod shared;

use crate::shared::Helpers;

#[actix_web::test]
async fn test_health_check() {
    // Arrange
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(format!("{test_app}/health_check"))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
}
