use actix_web::{web::Data, Error};
use mongodb::{
    bson::{doc, oid::ObjectId},
    results::InsertOneResult,
    Database,
};

use super::models::User;

pub async fn create_user(
    db: &Data<Database>,
    new_user: User,
    hashed: String,
) -> Result<InsertOneResult, Error> {
    let new_doc = User {
        id: None,
        email: new_user.email.to_owned(),
        password: hashed,
        refresh_token: None,
    };
    let user = db
        .collection("user")
        .insert_one(new_doc, None)
        .await
        .ok()
        .expect("Error creating user");

    Ok(user)
}

pub async fn find_by_email(db: &Data<Database>, email: String) -> Option<User> {
    let filter = doc! {"email": email};
    let user_detail = db
        .collection::<User>("user")
        .find_one(filter, None)
        .await
        .ok()?;

    user_detail
}

pub async fn find_by_id(db: &Data<Database>, id: ObjectId) -> Option<User> {
    let filter = doc! {"_id": id};
    let user_detail = db
        .collection::<User>("user")
        .find_one(filter, None)
        .await
        .ok()?;

    user_detail
}

pub async fn update_refresh_token(
    db: &Data<Database>,
    id: ObjectId,
    refresh_token: String,
) -> Option<User> {
    let filter = doc! {"_id": id};
    let update = doc! { "$set": doc! {"refreshToken": refresh_token} };
    let user_detail = db
        .collection::<User>("user")
        .find_one_and_update(filter, update, None)
        .await
        .ok()?;

    user_detail
}
