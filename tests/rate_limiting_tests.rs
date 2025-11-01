mod shared;
use shared::Helpers;

use crate::shared::EmailRequest;

#[actix_web::test]
async fn test_passing_rate_limits() {
    // Arrange
    let test_app = Helpers::init_config().await;
    let client = reqwest::Client::new();

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    let body = EmailRequest {
        email: "hakouguelfen@gmail.com".into(),
    };

    // Act
    for _ in 0..5 {
        let response = client
            .post(format!("{}/auth/password/forgot", test_app.address))
            .json(&body)
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());
    }

    let response = client
        .post(format!("{}/auth/password/forgot", test_app.address))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert_eq!(
        429,
        response.status().as_u16(),
        "The API did not fail when the payload was: {}",
        "Passed the rate limit of 5 attemps per hour"
    );
}
