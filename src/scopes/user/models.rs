use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role {
    #[default]
    User,
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub username: String,
    pub email: String,
    pub password: String,
    pub role: Role,

    #[serde(rename = "isPremium")]
    pub is_premium: bool,
}

#[derive(Serialize)]
pub struct UserResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    #[serde(rename = "isPremium")]
    pub is_premium: bool,
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

    pub fn as_response(self) -> UserResponse {
        UserResponse {
            // FIXME: dont use unwrap
            id: self.id.unwrap().to_string(),
            email: self.email,
            username: self.username,
            role: self.role,
            is_premium: self.is_premium,
        }
    }
}
