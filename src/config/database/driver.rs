#[derive(Debug, Default, Clone, Copy, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub enum DatabaseDriver {
    #[default]
    SQLite,
    PostgreSQL,
    MongoDB,
}

impl DatabaseDriver {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseDriver::SQLite => "sqlite",
            DatabaseDriver::MongoDB => "mongodb",
            DatabaseDriver::PostgreSQL => "postgresql",
        }
    }
    pub fn _is_sql(&self) -> bool {
        matches!(self, DatabaseDriver::SQLite | DatabaseDriver::PostgreSQL)
    }

    pub fn _is_nosql(&self) -> bool {
        matches!(self, DatabaseDriver::MongoDB)
    }
}
impl std::fmt::Display for DatabaseDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for DatabaseDriver {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "sqlite" => Ok(Self::SQLite),
            "mongodb" => Ok(Self::MongoDB),
            "postgresql" => Ok(Self::PostgreSQL),
            other => Err(format!(
                "{} is not supported database. Use either `sqlite`, `postgresql` or `mongodb`",
                other
            )),
        }
    }
}
