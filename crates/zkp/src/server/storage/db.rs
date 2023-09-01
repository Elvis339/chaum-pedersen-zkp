use std::collections::HashMap;

use sled::{Db, Tree};

use crate::storage::StorageError::{DeleteFailed, GetFailed, InsertFailed, NotFound, TreeNotFound};
use crate::storage::StorageResult;

/// The `StorageTree` enum specifies the different collections or trees
/// that can be used in the storage backend.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub enum StorageTree {
    Auth,
    Challenge,
}

type Key = Vec<u8>;
type Value = Vec<u8>;

pub struct KeyValueStorage {
    db: Db,
    trees: HashMap<StorageTree, Tree>,
}

impl KeyValueStorage {
    pub fn new() -> Self {
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
    pub(crate) fn insert(
        &mut self,
        collection: StorageTree,
        key: &Key,
        value: Value,
    ) -> StorageResult<()> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;

        match tree.insert(key, value) {
            Ok(_) => Ok(()),
            Err(e) => Err(InsertFailed(format!("Insert failed with error: {:?}", e))),
        }
    }

    pub(crate) fn get(&self, collection: StorageTree, key: &Key) -> StorageResult<Value> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;

        match tree.get(key) {
            Ok(Some(ivec)) => Ok(ivec.to_vec()),
            Ok(None) => Err(NotFound),
            Err(e) => Err(GetFailed(format!("Get failed with error {:?}", e))),
        }
    }

    pub(crate) fn upsert(
        &mut self,
        collection: StorageTree,
        key: &Key,
        value: Value,
    ) -> StorageResult<()> {
        self.insert(collection, key, value)
    }

    pub(crate) fn delete(&mut self, collection: StorageTree, key: &Key) -> StorageResult<()> {
        let tree = self.trees.get(&collection).ok_or(TreeNotFound)?;

        match tree.remove(key) {
            Ok(_) => Ok(()),
            Err(_) => Err(DeleteFailed),
        }
    }

    pub(crate) fn exists(&self, collection: StorageTree, key: &Key) -> bool {
        self.trees
            .get(&collection)
            .map(|tree| tree.contains_key(key).unwrap_or(false))
            .unwrap_or(false)
    }
}
