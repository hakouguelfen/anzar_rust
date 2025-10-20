use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use mongodb::bson::oid::ObjectId;
use validator::ValidationError;

pub fn validate_token(token: &str) -> Result<(), ValidationError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ValidationError::new("invalid_base64_token"))?;

    Ok(())
}

pub fn validate_objectid(id: &str) -> Result<(), ValidationError> {
    ObjectId::parse_str(id).map_err(|_| ValidationError::new("invalid ObjectId"))?;

    Ok(())
}
