use super::*;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Default)]
pub struct MemoryKeyStore(RwLock<HashMap<Bytes, Bytes>>);

impl KeyStore for MemoryKeyStore {
    fn store(&self, key: &Bytes, val: &Bytes) -> Result<()> {
        let mut key_store = self
            .0
            .write()
            .map_err(|err| Error::Other(err.to_string()))?;
        key_store.insert(key.clone(), val.clone());
        Ok(())
    }

    fn retrieve(&self, key: &Bytes) -> Option<Bytes> {
        let key_store = self.0.read().ok()?;
        key_store.get(key).cloned()
    }

    fn delete(&self, key: &Bytes) -> Option<Bytes> {
        let mut key_store = self.0.write().ok()?;
        key_store.remove(key)
    }
}
