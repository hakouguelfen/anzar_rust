use crate::extractors::AuthToken;
use actix_web::{web, HttpResponse, Scope};
use mongodb::{Database, bson::oid::ObjectId};

pub mod handler;
pub mod models;

async fn find_by_id(_: AuthToken, db: web::Data<Database>, id: web::Path<String>) -> HttpResponse {
    let user_id = ObjectId::parse_str(id.into_inner());
    if let Err(_) = user_id {
        return HttpResponse::Unauthorized().body("Error parsing objectId");
    }

    match handler::find_by_id(&db, user_id.unwrap()).await {
        Some(user) => HttpResponse::Ok().json(user),
        None => HttpResponse::NotFound().body("User not found"),
    }
}

pub fn user_scope() -> Scope {
    web::scope("/user").route("/{id}", web::get().to(find_by_id))
}
