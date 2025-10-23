use std::marker::PhantomData;

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sqlx::{FromRow, Pool, Sqlite, query::QueryAs, sqlite::SqliteArguments};

use crate::{adapters::traits::DatabaseAdapter, error::Error};

#[derive(sqlx::FromRow)]
struct IdResult {
    id: String,
}

pub struct SQLiteAdapter<T: Send + Sync> {
    pool: Pool<Sqlite>,
    table: String,
    _phantom: PhantomData<T>,
}

impl<T: Send + Sync> SQLiteAdapter<T> {
    pub fn new(db: &Pool<Sqlite>, table: &str) -> Self {
        SQLiteAdapter {
            pool: db.clone(),
            table: table.into(),
            _phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<T> DatabaseAdapter<T> for SQLiteAdapter<T>
where
    T: Send
        + Sync
        + Serialize
        + DeserializeOwned
        + 'static
        + for<'r> FromRow<'r, sqlx::sqlite::SqliteRow>
        + Unpin,
{
    async fn insert(&self, data: T) -> Result<String, Error> {
        let value = serde_json::to_value(data).unwrap();
        let obj = value.as_object().unwrap();

        let columns: Vec<_> = obj.keys().cloned().collect();
        let values = obj
            .values()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let columns = columns.join(",");
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({}) RETURNING id",
            self.table, columns, values
        );

        let row: IdResult = sqlx::query_as(sql.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                dbg!(&e);
                Error::DatabaseError(e.to_string())
            })?;

        Ok(row.id)
    }

    async fn find_one(&self, filter: Value) -> Result<Option<T>, Error> {
        let obj = _parse_to_map(filter)?;
        let where_clause = _parse_to_sql(&obj, " AND ");

        let sql = format!("SELECT * FROM {} WHERE {}", self.table, where_clause);
        let mut query = sqlx::query_as::<_, T>(&sql);

        for (_, v) in obj.iter() {
            query = _bind_value(query, v.to_owned());
        }

        query
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    async fn find_one_and_update(&self, filter: Value, update: Value) -> Result<Option<T>, Error> {
        let obj_update = _parse_to_map(update)?;
        let clause_update = _parse_to_sql(&obj_update, ", ");

        let obj_filter = _parse_to_map(filter)?;
        let clause_filter = _parse_to_sql(&obj_filter, " AND ");

        let sql = format!(
            "UPDATE {} SET {} WHERE {} RETURNING *",
            self.table, clause_update, clause_filter
        );
        let mut query = sqlx::query_as::<_, T>(&sql);

        for (_, v) in obj_update.iter() {
            query = _bind_value(query, v.to_owned());
        }
        for (_, v) in obj_filter.iter() {
            query = _bind_value(query, v.to_owned());
        }

        query
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    async fn update_many(&self, filter: Value, update: Value) -> Result<(), Error> {
        let obj_update = _parse_to_map(update)?;
        let clause_update = _parse_to_sql(&obj_update, ", ");

        let obj_filter = _parse_to_map(filter)?;
        let clause_filter = _parse_to_sql(&obj_filter, " AND ");

        let sql = format!(
            "UPDATE {} SET {} WHERE {} RETURNING *",
            self.table, clause_update, clause_filter
        );
        let mut query = sqlx::query_as::<_, T>(&sql);

        for (_, v) in obj_update.iter() {
            query = _bind_value(query, v.to_owned());
        }
        for (_, v) in obj_filter.iter() {
            query = _bind_value(query, v.to_owned());
        }

        query.fetch_optional(&self.pool).await.map_err(|e| {
            dbg!(&e);
            Error::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    async fn delete_one(&self, _filter: Value) -> Result<(), Error> {
        Ok(())
    }
    async fn delete_many(&self, _filter: Value) -> Result<(), Error> {
        Ok(())
    }
}

fn _parse_to_map(data: Value) -> Result<Map<String, Value>, Error> {
    let value = serde_json::to_value(data).unwrap();
    let obj = value.as_object().unwrap();
    if obj.is_empty() {
        return Err(Error::InternalServerError("parsing error".into()));
    }

    Ok(obj.to_owned())
}

fn _parse_to_sql(obj: &Map<String, Value>, join: &str) -> String {
    let conditions: Vec<String> = obj.keys().map(|k| format!("{} = ?", k)).collect();
    conditions.join(join)
}

fn _bind_value<'q, T>(
    query: QueryAs<'q, Sqlite, T, SqliteArguments<'q>>,
    v: Value,
) -> QueryAs<'q, Sqlite, T, SqliteArguments<'q>> {
    match v {
        serde_json::Value::String(s) => query.bind(s),
        serde_json::Value::Number(n) if n.is_i64() => query.bind(n.as_i64()),
        serde_json::Value::Number(n) if n.is_f64() => query.bind(n.as_f64()),
        serde_json::Value::Bool(b) => query.bind(b),
        serde_json::Value::Null => query.bind::<Option<String>>(None),
        _ => query.bind(v.to_string()),
    }
}
