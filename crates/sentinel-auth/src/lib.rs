//! Local authentication primitives: password hashing, opaque secrets, cookie
//! and CSRF policy. Pure computation and byte formatting; nothing here reads a
//! database, a clock or a request. Durable sessions live in `sentinel-store`.
//!
//! No credential material is ever formatted through `Debug`/`Display`.

pub mod cookie;
pub mod mfa;
pub mod password;
pub mod sealed;
pub mod secret;
pub mod token;
