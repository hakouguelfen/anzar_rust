use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mongodb::bson::oid::ObjectId;
use validator::ValidationError;

pub fn validate_token(token: &str) -> Result<(), ValidationError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ValidationError::new("invalid_base64_token"))?;

    if decoded.len() < 32 {
        return Err(ValidationError::new("token_too_short"));
    }

    Ok(())
}

pub fn validate_objectid(id: &str) -> Result<(), ValidationError> {
    ObjectId::parse_str(id).map_err(|_| ValidationError::new("invalid ObjectId"))?;

    Ok(())
}
