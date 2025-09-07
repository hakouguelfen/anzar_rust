use mongodb::bson::oid::ObjectId;
use serde_json::Value;

use crate::adapters::database_adapter::Document;

pub struct Parser {
    adapter_type: AdapterType,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum AdapterType {
    #[default]
    Sqlite,
    PostgreSql,
    MongoDB,
}

impl Parser {
    pub fn mode(adapter_type: AdapterType) -> Self {
        Self { adapter_type }
    }

    pub fn convert(&self, data: Document) -> Document {
        match &self.adapter_type {
            AdapterType::MongoDB => self.mongo_convert(data),
            AdapterType::Sqlite => self.sqlite_convert(data),
            AdapterType::PostgreSql => self.sqlite_convert(data),
        }
    }

    fn mongo_convert(&self, mut doc: Document) -> Document {
        const IDS: [&str; 4] = ["id", "_id", "user_id", "userId"];
        if let Value::Object(map) = &mut doc {
            for (key, value) in map.iter_mut() {
                if IDS.contains(&key.as_str())
                    && let Some(s) = value.as_str()
                    && let Ok(oid) = ObjectId::parse_str(s)
                {
                    *value = serde_json::to_value(oid).unwrap();
                }
            }
        }

        doc
    }

    fn sqlite_convert(&self, doc: Document) -> Document {
        const MONGO_KEYWORDS: [&str; 3] = ["$set", "$inc", "$unset"];
        if let Value::Object(map) = doc.clone() {
            for (key, value) in map {
                if !MONGO_KEYWORDS.contains(&key.as_str()) {
                    continue;
                }
                if let Value::Object(inner_doc) = value {
                    return Value::Object(inner_doc);
                }
            }
        }

        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_basic() {
        let input = json!({"id": "123AZEDJ"});
        let output = Parser::mode(AdapterType::Sqlite).convert(input.clone());

        let expected = json!({"id": "123AZEDJ"});

        assert_eq!(output, expected);
    }

    #[test]
    fn test_single_val() {
        let input = json!({ "$set": json!({"password": "password"}) });
        let output = Parser::mode(AdapterType::Sqlite).convert(input.clone());

        let expected = json!({"password": "password"});

        assert_eq!(output, expected);
    }

    #[test]
    fn test_multiple_vals() {
        let input = json!({
            "$set": json! ({
                "lastPasswordReset": "time",
                "passwordResetCount": 0,
                "failedResetAttempts": 0
            })
        });
        let output = Parser::mode(AdapterType::Sqlite).convert(input.clone());

        let expected = json! ({
            "lastPasswordReset": "time",
            "passwordResetCount": 0,
            "failedResetAttempts": 0
        });

        assert_eq!(output, expected);
    }
}
