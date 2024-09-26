use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role {
    User,
    Admin,
}
impl Default for Role {
    fn default() -> Self {
        Role::User
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct User {
    #[serde(serialize_with = "serialize_object_id")]
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub username: String,
    pub email: String,
    pub password: String,
    pub role: Role,

    #[serde(rename = "isPremium")]
    pub is_premium: bool,
}

fn serialize_object_id<S>(id: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match id {
        Some(id) => serializer.serialize_str(&id.to_string()),
        None => serializer.serialize_none(),
    }
}

impl User {
    pub fn new(user: User) -> Self {
        User {
            id: None,
            username: user.username,
            email: user.email,
            role: Role::User,
            password: "".to_string(),
            is_premium: false,
        }
    }

    pub fn with_id(&mut self, id: ObjectId) {
        self.id = Some(id);
    }

    pub fn with_password(mut self, password: String) -> Self {
        self.password = password;
        self
    }
}
