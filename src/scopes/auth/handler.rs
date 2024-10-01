use actix_web::{
    web::{self, Data, Json, Query},
    HttpResponse, Scope,
};
use log::info;
use mongodb::bson::oid::ObjectId;

use crate::core::repository::repository_manager::RepositoryManager;

use super::user::User;
use super::Claims;
use super::{
    email::manager::Email,
    models::{EmailRequest, LoginRequest, TokenQuery},
};
use super::{error::Result, models::AuthPayload};
use super::{extenstion::AuthResponseTrait, repository};
use uuid::Uuid;

async fn login(req: Json<LoginRequest>, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user: User = repository::check_credentials(&repo, req.into_inner()).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::load_tokens(tokens, user.as_response())))?
}

async fn register(req: Json<User>, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    info!("Registering");
    let user: User = repository::create_user(&repo, req.into_inner()).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::load_tokens(tokens, user.as_response())))?
}

async fn refresh_token(
    payload: AuthPayload,
    repo: Data<RepositoryManager>,
) -> Result<HttpResponse> {
    // NOTE: maybe save valid tokens to user doc
    let user: User = repository::validate_token(&repo, payload).await?;

    repository::issue_and_save_tokens(&repo, &user)
        .await
        .map(|tokens| Ok(HttpResponse::Ok().json(tokens)))?
}

async fn logout(claims: Claims, repo: Data<RepositoryManager>) -> Result<HttpResponse> {
    let user_id: ObjectId = ObjectId::parse_str(claims.sub).unwrap_or_default();
    repository::logout(repo, user_id)
        .await
        .map(|user| Ok(HttpResponse::Ok().json(user)))?
}

async fn forgot_password(
    req: Json<EmailRequest>,
    repo: Data<RepositoryManager>,
) -> Result<HttpResponse> {
    // get email from payload
    let email: String = req.into_inner().email;

    // chkeck if email exist in DB
    let user: User = repository::find_by_email(&repo, email).await?;

    // generate a time limited token
    let _token = Uuid::new_v4();

    // Save the token into a database
    //
    // compose an email with token: exp-> api/reset-password?token=xxxxxxx
    Email::new()
        .with_sender("hakouklvn79@gmail.com")
        .with_reciever(user.email)
        .send()?;
    //
    // send confirmation email to check the inbox
    Ok(HttpResponse::Ok().json("email has been sent"))
}

async fn reset_password(
    _repo: Data<RepositoryManager>,
    query: Query<TokenQuery>,
) -> Result<HttpResponse> {
    let _token: &str = &query.token;
    // Checks the database for a matching token

    // Verifies the token isn't expired or already used

    // If valid, allows the password reset for the associated user

    // Marks the token as used in the database

    todo!("")
    // repository::search(&db, &query.token)
    //     .await
    //     .map(|books| HttpResponse::Ok().json(books))
    //     .map_err(|_| Error::NotFound)
}

pub fn auth_scope() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/refreshToken", web::post().to(refresh_token))
        .route("/logout", web::post().to(logout))
        .route("/forgot-password", web::post().to(forgot_password))
        .route("/reset-password", web::post().to(reset_password))
}
