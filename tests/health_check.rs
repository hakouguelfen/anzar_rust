mod common;

use common::Common;
use uuid::Uuid;

#[actix_web::test]
async fn test_health_check() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name).await;

    let client = reqwest::Client::new();

    dbg!(format!("{address}/health_check"));

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
