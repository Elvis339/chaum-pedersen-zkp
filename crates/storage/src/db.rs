use std::collections::HashMap;

use sled::{Db, Tree};

use crate::StorageError::{
    DeleteFailed, DeserializationFailed, GetFailed, InsertFailed, NotFound, SerializationFailed,
    TreeNotFound,
};
use crate::StorageResult;

/// The `StorageTree` enum specifies the different collections or trees
/// that can be used in the storage backend.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub enum StorageTree {
    Auth,
    Challenge,
}

type Key = Vec<u8>;

pub struct KeyValueStorage {
    db: Db,
    trees: HashMap<StorageTree, Tree>,
}

impl KeyValueStorage {
    pub fn open() -> Self {
        let db = sled::open("db").expect("failed to open db");
        let trees = [
            (StorageTree::Auth, db.open_tree("auth").unwrap()),
            (StorageTree::Challenge, db.open_tree("challenge").unwrap()),
        ]
            .iter()
            .cloned()
            .collect();

        Self { db, trees }
    }
}

impl KeyValueStorage {
    pub fn insert<T: serde::Serialize>(
        &mut self,
        collection: StorageTree,
        key: &Key,
        value: T,
    ) -> StorageResult<()> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;
        let serialized_value = bincode::serialize(&value)
            .map_err(|e| SerializationFailed(format!("Serialization failed: {:?}", e)))?;

        match tree.insert(key, serialized_value) {
            Ok(_) => Ok(()),
            Err(e) => Err(InsertFailed(format!("Insert failed with error: {:?}", e))),
        }
    }

    pub fn get<T: serde::de::DeserializeOwned>(
        &self,
        collection: StorageTree,
        key: &Key,
    ) -> StorageResult<T> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;

        match tree.get(key) {
            Ok(Some(ivec)) => {
                let bytes = ivec.to_vec();
                Ok(bincode::deserialize(&bytes)
                    .map_err(|e| DeserializationFailed(format!("Deserialization failed: {}", e)))?)
            }
            Ok(None) => Err(NotFound),
            Err(e) => Err(GetFailed(format!("Get failed with error {:?}", e))),
        }
    }

    pub fn upsert<T: serde::Serialize>(
        &mut self,
        collection: StorageTree,
        key: &Key,
        value: T,
    ) -> StorageResult<()> {
        self.insert::<T>(collection, key, value)
    }

    pub fn delete(&mut self, collection: StorageTree, key: &Key) -> StorageResult<()> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;

        match tree.remove(key) {
            Ok(_) => Ok(()),
            Err(_) => Err(DeleteFailed),
        }
    }

    pub fn exists(&self, collection: StorageTree, key: &Key) -> bool {
        self.trees
            .get(&collection)
            .map(|tree| tree.contains_key(key).unwrap_or(false))
            .unwrap_or(false)
    }
}
