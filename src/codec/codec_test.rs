use super::*;

use serde::{self, de::DeserializeOwned};
use std::fmt::Write;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub(crate) fn load_test_vector<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

/// Convert `bytes` to a hex string.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for &b in bytes {
        write!(&mut hex, "{b:02X}").expect("Unable to write to string");
    }
    hex
}

/// Convert a hex string to a byte vector.
pub(crate) fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        bytes.push(
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("An unexpected error occurred."),
        );
    }
    bytes
}
