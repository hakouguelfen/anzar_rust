use mongodb::bson::oid::ObjectId;
use serde_json::Value;

use crate::{adapters::database_adapter::Document, scopes::auth::Error};

pub struct ParsedObjectId(pub Document);
const BSON_ID: [&str; 3] = ["_id", "user_id", "userId"];

impl TryFrom<Document> for ParsedObjectId {
    type Error = Error;

    fn try_from(mut doc: Document) -> Result<Self, Self::Error> {
        if let Value::Object(map) = &mut doc {
            for (key, value) in map.iter_mut() {
                if BSON_ID.contains(&key.as_str())
                    && let Some(s) = value.as_str()
                {
                    let oid = ObjectId::parse_str(s).map_err(|_| Error::DatabaseError)?;
                    *value = serde_json::to_value(oid).unwrap();
                }
            }
        }

        Ok(Self(doc))
    }
}
