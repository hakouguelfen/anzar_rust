use actix_web::{web, HttpResponse};
use bcrypt::{hash, verify, DEFAULT_COST};
use mongodb::{bson::oid::ObjectId, Database};

use super::{
    jwt::{self, Tokens},
    LoginRequest,
};
use crate::{
    extractors::AuthToken,
    scopes::user::{handler, models::User},
};

pub async fn login(
    db: web::Data<Database>,
    req: LoginRequest,
    secret: String,
) -> Result<(User, Tokens), HttpResponse> {
    let user_detail = handler::find_by_email(&db, req.email.to_string()).await;

    if let None = user_detail {
        return Err(HttpResponse::Unauthorized().body("user not found"));
    }
    let user = user_detail.unwrap();
    let user_id: ObjectId = user.id.expect("ObjectId convertion error");

    let is_valid: bool = verify(&req.password, &user.password).unwrap_or(false);
    if !is_valid {
        return Err(HttpResponse::Unauthorized().body("password wrong"));
    }
    Ok(sync_token(&db, user_id, secret).await?)
}

pub async fn register(
    db: web::Data<Database>,
    req: User,
    secret: String,
) -> Result<(User, Tokens), HttpResponse> {
    let hashed = hash(&req.password, DEFAULT_COST);
    if let Err(_) = hashed {
        return Err(HttpResponse::InternalServerError().body("password hashing error"));
    }

    let user_detail = handler::create_user(&db, req, hashed.unwrap()).await;
    if let Err(_) = user_detail {
        return Err(HttpResponse::Unauthorized().body("User creation error"));
    }

    let user = user_detail.unwrap();
    let user_id: ObjectId = user
        .inserted_id
        .as_object_id()
        .expect("filed to make an objectId");

    Ok(sync_token(&db, user_id, secret).await?)
}

pub async fn refresh_user_token(
    auth_token: AuthToken,
    db: web::Data<Database>,
    secret: String,
) -> Result<Tokens, HttpResponse> {
    // get user
    let user_id = ObjectId::parse_str(auth_token.user_id);
    if let Err(_) = user_id {
        return Err(HttpResponse::Unauthorized().body("Error parsing objectId"));
    }
    let user_object_id = user_id.unwrap();

    let user_detail = handler::find_by_id(&db, user_object_id).await;
    if let None = user_detail {
        return Err(HttpResponse::Unauthorized().body("User not found"));
    }
    let user: User = user_detail.unwrap();

    // get token
    let rf_token_option = auth_token.refresh_token;
    if let None = rf_token_option {
        return Err(HttpResponse::InternalServerError().body("retrieve token failure"));
    }
    let refresh_token: String = rf_token_option.unwrap();

    // compare hash(refreshToken) with user.refreshToken
    let is_valid: bool = verify(
        &refresh_token,
        &user.refresh_token.unwrap_or(String::from("")),
    )
    .unwrap_or(false);
    if !is_valid {
        return Err(HttpResponse::Unauthorized().body("comapre token failure"));
    }

    let response = sync_token(&db, user_object_id, secret).await;
    if let Err(_) = response {
        return Err(HttpResponse::Unauthorized().body("comapre token failure"));
    }

    Ok(response.unwrap().1)
}

pub async fn sync_token(
    db: &web::Data<Database>,
    user_id: ObjectId,
    secret: String,
) -> Result<(User, Tokens), HttpResponse> {
    let tokens_response = jwt::encode_tokens(user_id.to_string(), secret);
    if let Err(_) = tokens_response {
        return Err(HttpResponse::Unauthorized().body("Token creation error"));
    }

    let tokens = tokens_response.unwrap();

    let hashed = hash(&tokens.refresh_token, DEFAULT_COST);
    if let Err(_) = hashed {
        return Err(HttpResponse::InternalServerError().body("token hashing error"));
    }

    let user_detail = handler::update_refresh_token(&db, user_id, hashed.unwrap()).await;

    if let None = user_detail {
        return Err(HttpResponse::InternalServerError().body("update token failed"));
    }

    Ok((user_detail.unwrap(), tokens))
}
