use std::fmt;

pub mod db;
pub mod model;

#[derive(Debug, Clone)]
pub enum StorageError {
    TreeNotFound,
    NotFound,
    InsertFailed(String),
    SerializationFailed(String),
    DeserializationFailed(String),
    UpdateFailed,
    DeleteFailed,
    GetFailed(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageError::TreeNotFound => write!(f, "Tree not found in storage"),
            StorageError::NotFound => write!(f, "Item not found in storage"),
            StorageError::InsertFailed(s) => write!(f, "Failed to insert item: {}", s),
            StorageError::SerializationFailed(s) => write!(f, "Failed to serialize item: {}", s),
            StorageError::DeserializationFailed(s) => {
                write!(f, "Failed to deserialize item: {}", s)
            }
            StorageError::UpdateFailed => write!(f, "Failed to update item"),
            StorageError::DeleteFailed => write!(f, "Failed to delete item"),
            StorageError::GetFailed(s) => write!(f, "Failed to get item: {}", s),
        }
    }
}

pub type StorageResult<T> = Result<T, StorageError>;
