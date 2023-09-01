pub mod db;
pub mod model;

#[derive(Debug, Clone)]
pub enum StorageError {
    TreeNotFound,
    NotFound,
    InsertFailed(String),
    UpdateFailed,
    DeleteFailed,
    GetFailed(String),
    // More error types as needed
}

pub type StorageResult<T> = Result<T, StorageError>;
