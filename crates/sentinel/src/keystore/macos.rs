//! macOS Keychain backend: one generic password per profile in the login
//! keychain, service `sentinel`, account `sentinel:{issuer}:{profile}`.

use std::io;

use security_framework::{
    base::Error as SecError,
    passwords::{delete_generic_password, get_generic_password, set_generic_password},
};

const SERVICE: &str = "sentinel";
/// `errSecItemNotFound`.
const NOT_FOUND: i32 = -25300;

fn io_error(error: SecError) -> io::Error {
    io::Error::other(format!("keychain error {}", error.code()))
}

pub fn read(key: &str) -> io::Result<Option<Vec<u8>>> {
    match get_generic_password(SERVICE, key) {
        Ok(blob) => Ok(Some(blob)),
        Err(e) if e.code() == NOT_FOUND => Ok(None),
        Err(e) => Err(io_error(e)),
    }
}

pub fn write(key: &str, blob: &[u8]) -> io::Result<()> {
    set_generic_password(SERVICE, key, blob).map_err(io_error)
}

pub fn delete(key: &str) -> io::Result<()> {
    match delete_generic_password(SERVICE, key) {
        Err(e) if e.code() != NOT_FOUND => Err(io_error(e)),
        _ => Ok(()),
    }
}
