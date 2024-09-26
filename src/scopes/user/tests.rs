// use super::*;
// use actix_web::dev::ServiceResponse;
// use actix_web::{test, App};
// use async_trait::async_trait;
// use mockall::mock;
// use repository::UserRepo;

// use mongodb::bson::oid::ObjectId;
// use mongodb::error::Error;
// use mongodb::results::InsertOneResult;

// // Define a mock repository
// mock! {
//     pub UserRepo {}

//     #[async_trait]
//     impl UserRepo for MockUserRepo {
//         async fn create_user(&self, user: &User) -> Result<InsertOneResult, Error>;
//         async fn find_by_email(&self, email: &str) -> Option<User>;
//         async fn find_by_id(&self, id: ObjectId) -> Option<User>;
//         async fn update_refresh_token(&self, id: ObjectId, refresh_token: String) -> Option<User>;
//         async fn activate_account(&self, id: ObjectId) -> Option<User>;
//         async fn remove_refresh_token(&self, id: ObjectId) -> Option<User>;
//     }
// }

// #[actix_web::test]
// async fn test_find_user() {
//     MockUserRepo::new().UserRepo_expectations()
//     // Create a mock repository
//     let mut mock_repo = MockUserRepo::new();

//     // mock_repo
//     //     .expect_find_by_id()
//     //     .return_once(|_| Some(User { /* populate with test data */ }));

//     // let repo_manager = web::Data::new(RepositoryManager {
//     //     user_repo: mock_repo,
//     //     // initialize other repos if needed
//     // });

//     let app = test::init_service(
//         App::new()
//             .app_data(repo_manager.clone())
//             .service(user_scope()),
//     )
//     .await;

//     let req = test::TestRequest::get().uri("/user").to_request();
//     let resp: ServiceResponse = test::call_service(&app, req).await;

//     assert_eq!(resp.status(), http::StatusCode::OK);
//     // Further assertions based on response
// }
