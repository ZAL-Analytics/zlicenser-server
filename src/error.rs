#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("record not found")]
    NotFound,
    #[error("unique constraint violation: {0}")]
    Conflict(String),
    #[error("foreign key constraint violation: {0}")]
    ForeignKeyViolation(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("migration error: {0}")]
    Migration(String),
    #[error("corrupt stored data: {0}")]
    Corrupt(String),
}

#[cfg(feature = "storage-sqlite")]
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Error::NotFound,
            sqlx::Error::Database(db) => {
                let msg = db.message().to_string();
                if db.is_unique_violation() {
                    Error::Conflict(msg)
                } else if db.is_foreign_key_violation() || msg.contains("FOREIGN KEY") {
                    Error::ForeignKeyViolation(msg)
                } else {
                    Error::Database(msg)
                }
            }
            _ => Error::Database(e.to_string()),
        }
    }
}

#[cfg(all(feature = "storage-postgres", not(feature = "storage-sqlite")))]
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Error::NotFound,
            sqlx::Error::Database(db) => {
                let msg = db.message().to_string();
                if db.is_unique_violation() {
                    Error::Conflict(msg)
                } else if db.is_foreign_key_violation() {
                    Error::ForeignKeyViolation(msg)
                } else {
                    Error::Database(msg)
                }
            }
            _ => Error::Database(e.to_string()),
        }
    }
}
