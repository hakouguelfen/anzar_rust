use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize_object_id_as_string<S>(id: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Ok(oid) = ObjectId::parse_str(id) {
        serializer.serialize_some(&oid)
    } else {
        serializer.serialize_some(id)
    }
}

pub fn deserialize_object_id_as_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let oid: Option<ObjectId> = Option::deserialize(deserializer)?;
    Ok(oid.map(|o| o.to_hex()))
}

pub fn deserialize_object_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let oid: ObjectId = ObjectId::deserialize(deserializer)?;
    Ok(oid.to_hex())
}
