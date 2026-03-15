// normalize_db_driver
pub fn get_db_type(s: &str) -> &str {
    match s.to_lowercase().as_str() {
        "postgres" | "postgresql" => "PostgreSQL",
        "mongodb" | "mongo" => "MongoDB",
        "sqlite" => "SQLite",
        _ => "SQLite",
    }
}
