mod shared;
use anzar::{config::AuthStrategy, scopes::auth::AuthResponse};
use shared::Helpers;

const X_REFRESH_TOKEN: &str = "x-refresh-token";

#[actix_web::test]
async fn test_logout_success() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let refresh_token: &str = &tokens.refresh;

        // Logout
        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {refresh_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert!(response.status().is_success());
    }
}

#[actix_web::test]
async fn test_logout_with_invalid_token() {
    let test_app = Helpers::init_config().await;

    // Create User
    let response = Helpers::create_user(&test_app).await;
    assert!(response.status().is_success());

    // Login
    let response = Helpers::login(&test_app).await;
    assert!(response.status().is_success());

    let auth_response: AuthResponse = response.json().await.unwrap();

    if test_app.configuration.auth.strategy == AuthStrategy::Jwt
        && let Some(tokens) = &auth_response.tokens
    {
        let access_token: &str = &tokens.access;

        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .header(X_REFRESH_TOKEN, format!("Bearer {access_token}"))
            .send()
            .await
            .expect("Failed to execute request.");
        assert_eq!(
            401,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            "using accessToken instead of refresh_token"
        );

        let response = test_app
            .client
            .post(format!("{}/auth/logout", test_app.address))
            .send()
            .await
            .expect("Failed to execute request.");
        assert_eq!(
            401,
            response.status().as_u16(),
            "The API did not fail when the payload was: {}",
            "not sending a refresh_token"
        );
    }
}
