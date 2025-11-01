use mongodb::bson::oid::ObjectId;
use serde_json::Value;

use crate::config::DatabaseDriver;

pub struct Parser {
    database_driver: DatabaseDriver,
}

impl Parser {
    pub fn mode(database_driver: DatabaseDriver) -> Self {
        Self { database_driver }
    }

    pub fn convert(&self, data: Value) -> Value {
        match &self.database_driver {
            DatabaseDriver::MongoDB => self.mongo_convert(data),
            DatabaseDriver::SQLite => self.sqlite_convert(data),
            DatabaseDriver::PostgreSQL => todo!(),
        }
    }

    fn mongo_convert(&self, mut doc: Value) -> Value {
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

    fn sqlite_convert(&self, doc: Value) -> Value {
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
        let output = Parser::mode(DatabaseDriver::SQLite).convert(input.clone());

        let expected = json!({"id": "123AZEDJ"});

        assert_eq!(output, expected);
    }

    #[test]
    fn test_single_val() {
        let input = json!({ "$set": json!({"password": "password"}) });
        let output = Parser::mode(DatabaseDriver::SQLite).convert(input.clone());

        let expected = json!({"password": "password"});

        assert_eq!(output, expected);
    }

    #[test]
    fn test_multiple_vals() {
        let input = json!({
            "$set": json! ({
                "lastPasswordReset": "time",
            })
        });
        let output = Parser::mode(DatabaseDriver::SQLite).convert(input.clone());

        let expected = json! ({
            "lastPasswordReset": "time",
        });

        assert_eq!(output, expected);
    }
}
