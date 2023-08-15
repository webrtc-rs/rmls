use super::*;
use serde::{self, de::DeserializeOwned};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub(crate) fn load_test_vector<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}
