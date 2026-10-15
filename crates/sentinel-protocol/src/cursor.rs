//! Cursors bind the tenant, so a cursor issued to one tenant is rejected for another.
use std::fmt;

use sentinel_core::TenantId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Seq(pub u64);

impl Seq {
    pub const START: Seq = Seq(0);
    #[must_use]
    pub const fn next(self) -> Seq {
        Seq(self.0.saturating_add(1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamKind {
    RunEvents = 1,
    AttemptLog = 2,
    TenantAudit = 3,
}

impl StreamKind {
    const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::RunEvents,
            2 => Self::AttemptLog,
            3 => Self::TenantAudit,
            _ => return None,
        })
    }
}

/// Binary layout (42 bytes): version(1) | tenant(16) | kind(1) | stream(16) | seq(8 BE).
/// Text form is `c1` followed by 84 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cursor {
    pub tenant: TenantId,
    pub kind: StreamKind,
    pub stream: [u8; 16],
    pub seq: Seq,
}

const VERSION: u8 = 1;
const RAW_LEN: usize = 1 + 16 + 1 + 16 + 8;
pub const CURSOR_TEXT_LEN: usize = 2 + RAW_LEN * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorError {
    Malformed,
    UnsupportedVersion,
    WrongTenant,
}

impl Cursor {
    fn to_bytes(self) -> [u8; RAW_LEN] {
        let mut out = [0u8; RAW_LEN];
        out[0] = VERSION;
        out[1..17].copy_from_slice(self.tenant.as_bytes());
        out[17] = self.kind as u8;
        out[18..34].copy_from_slice(&self.stream);
        out[34..42].copy_from_slice(&self.seq.0.to_be_bytes());
        out
    }

    pub fn parse(text: &str, caller: TenantId) -> Result<Self, CursorError> {
        let b = text.as_bytes();
        if b.len() != CURSOR_TEXT_LEN || &b[..2] != b"c1" {
            return Err(CursorError::Malformed);
        }
        let mut raw = [0u8; RAW_LEN];
        for (i, chunk) in b[2..].chunks_exact(2).enumerate() {
            raw[i] = (hex_val(chunk[0])? << 4) | hex_val(chunk[1])?;
        }
        if raw[0] != VERSION {
            return Err(CursorError::UnsupportedVersion);
        }
        let mut tenant = [0u8; 16];
        tenant.copy_from_slice(&raw[1..17]);
        let tenant = TenantId::from_bytes(tenant).map_err(|_| CursorError::Malformed)?;
        if tenant != caller {
            return Err(CursorError::WrongTenant);
        }
        let kind = StreamKind::from_u8(raw[17]).ok_or(CursorError::Malformed)?;
        let mut stream = [0u8; 16];
        stream.copy_from_slice(&raw[18..34]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&raw[34..42]);
        Ok(Self {
            tenant,
            kind,
            stream,
            seq: Seq(u64::from_be_bytes(seq)),
        })
    }
}

const fn hex_val(c: u8) -> Result<u8, CursorError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(CursorError::Malformed),
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let raw = self.to_bytes();
        let mut text = [0u8; CURSOR_TEXT_LEN];
        text[0] = b'c';
        text[1] = b'1';
        for (i, byte) in raw.iter().enumerate() {
            text[2 + i * 2] = HEX[(byte >> 4) as usize];
            text[3 + i * 2] = HEX[(byte & 0xF) as usize];
        }
        f.write_str(std::str::from_utf8(&text).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub next: Option<Cursor>,
    pub complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::RunId;

    #[test]
    fn cursor_round_trips_and_binds_tenant() {
        let tenant = TenantId::new();
        let run = RunId::new();
        let c = Cursor {
            tenant,
            kind: StreamKind::RunEvents,
            stream: *run.as_bytes(),
            seq: Seq(42),
        };
        let text = c.to_string();
        assert_eq!(text.len(), CURSOR_TEXT_LEN);
        assert!(text.starts_with("c1"));
        assert_eq!(Cursor::parse(&text, tenant), Ok(c));
        assert_eq!(
            Cursor::parse(&text, TenantId::new()),
            Err(CursorError::WrongTenant)
        );
        assert_eq!(
            Cursor::parse(&text[..text.len() - 1], tenant),
            Err(CursorError::Malformed)
        );
        assert_eq!(
            Cursor::parse(&text.to_uppercase(), tenant),
            Err(CursorError::Malformed)
        );
        let mut wrong_version = text.clone();
        wrong_version.replace_range(2..4, "02");
        assert_eq!(
            Cursor::parse(&wrong_version, tenant),
            Err(CursorError::UnsupportedVersion)
        );
        let mut bad_kind = text.clone();
        bad_kind.replace_range(36..38, "09");
        assert_eq!(
            Cursor::parse(&bad_kind, tenant),
            Err(CursorError::Malformed)
        );
    }

    #[test]
    fn seq_is_dense_and_saturating() {
        assert_eq!(Seq::START.next(), Seq(1));
        assert_eq!(Seq(u64::MAX).next(), Seq(u64::MAX));
        assert!(Seq(3) < Seq(4));
    }
}
