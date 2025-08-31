mod shared;

use crate::shared::{Common, register_context};
use uuid::Uuid;

#[actix_web::test]
async fn test_health_check() {
    // Arrange
    let db_name = Uuid::new_v4().to_string();
    let address = Common::spawn_app(db_name.clone()).await;
    let client = reqwest::Client::new();

    let db = format!("mongodb://localhost:27017/{db_name}");
    register_context(&address.address, db).await;

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
