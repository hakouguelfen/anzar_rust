mod common;

use common::Common;

#[actix_web::test]
async fn test_health_check() {
    // Arrange
    let address = Common::spawn_app().await;

    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(format!("{address}/health_check"))
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
