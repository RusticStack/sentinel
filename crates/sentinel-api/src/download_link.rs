//! Short-lived download links: a signed token naming one tenant's artifact and either one entry or a whole archive.
//!
//! A token is self-contained, so redemption costs one keyed MAC and one artifact lookup: no server-side record is
//! created or consumed, and a token may be redeemed as often as its short life allows. The MAC is a BLAKE3 keyed
//! hash under a subkey of the sealed master key's active epoch, and the epoch is part of the payload, so rotating the
//! key retires every link minted before it. Redemption re-checks what minting could not promise — the epoch is still
//! active, the clock is before the expiry, and the artifact is captured, retained and owned by an active tenant — and
//! answers every refusal as the same `not_found`, so the route reveals neither artifacts, tenants nor epochs.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sentinel_auth::sealed::Key;
use sentinel_core::{ArtifactId, TenantId, UnixMillis};

use crate::archive::Format;

const VERSION: u8 = 1;
const TAG_LEN: usize = 32;
/// Version, kind, tenant, artifact, expiry and epoch; an entry link adds its path before the tag.
const FIXED_LEN: usize = 1 + 1 + 16 + 16 + 8 + 4;
/// The manifest's own entry-path bound, so a link can name any entry its artifact holds.
pub(crate) const MAX_PATH: usize = 1024;
pub(crate) const DEFAULT_SECS: u64 = 300;
pub(crate) const MAX_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Archive(Format),
    Entry(String),
}

impl Target {
    /// One word for the access log; never the path itself.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Target::Archive(Format::Tar) => "tar",
            Target::Archive(Format::Zip) => "zip",
            Target::Entry(_) => "entry",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Link {
    pub tenant: TenantId,
    pub artifact: ArtifactId,
    pub target: Target,
    /// Wall-clock milliseconds; a token is valid while the clock reads before it.
    pub expires_ms: i64,
}

/// The token text for a link. The tag covers every byte before it, so no field can be changed independently.
pub(crate) fn mint(key: &Key, link: &Link, epoch: u32) -> String {
    let path = match &link.target {
        Target::Entry(path) => path.as_bytes(),
        Target::Archive(_) => &[],
    };
    let path_header = if path.is_empty() { 0 } else { 2 };
    let mut payload = Vec::with_capacity(FIXED_LEN + path_header + path.len() + TAG_LEN);
    payload.push(VERSION);
    payload.push(match link.target {
        Target::Archive(Format::Tar) => 0,
        Target::Archive(Format::Zip) => 1,
        Target::Entry(_) => 2,
    });
    payload.extend_from_slice(link.tenant.as_bytes());
    payload.extend_from_slice(link.artifact.as_bytes());
    payload.extend_from_slice(&link.expires_ms.to_be_bytes());
    payload.extend_from_slice(&epoch.to_be_bytes());
    if !path.is_empty() {
        payload.extend_from_slice(&(path.len() as u16).to_be_bytes());
        payload.extend_from_slice(path);
    }
    let tag = blake3::keyed_hash(key.link_key(), &payload);
    payload.extend_from_slice(tag.as_bytes());
    URL_SAFE_NO_PAD.encode(payload)
}

/// The link a token names, or `None` for anything that must not be distinguished from an unknown one: a malformed
/// token, a broken tag, another epoch's token, or one whose expiry has arrived.
pub(crate) fn verify(key: &Key, token: &str, now: UnixMillis, epoch: u32) -> Option<Link> {
    // A token longer than the largest link is refused before anything is decoded.
    let cap = (FIXED_LEN + 2 + MAX_PATH + TAG_LEN).saturating_mul(4) / 3 + 3;
    if token.len() > cap {
        return None;
    }
    let mut payload = Vec::with_capacity(token.len() * 3 / 4 + 3);
    URL_SAFE_NO_PAD.decode_vec(token, &mut payload).ok()?;
    if payload.len() < FIXED_LEN + TAG_LEN || payload[0] != VERSION {
        return None;
    }
    let (body, tag) = payload.split_at(payload.len() - TAG_LEN);
    let expected = blake3::keyed_hash(key.link_key(), body);
    if !tag_matches(expected.as_bytes(), tag) {
        return None;
    }
    let kind = body[1];
    let tenant = TenantId::from_bytes(<[u8; 16]>::try_from(&body[2..18]).ok()?).ok()?;
    let artifact = ArtifactId::from_bytes(<[u8; 16]>::try_from(&body[18..34]).ok()?).ok()?;
    let expires_ms = i64::from_be_bytes(<[u8; 8]>::try_from(&body[34..42]).ok()?);
    let token_epoch = u32::from_be_bytes(<[u8; 4]>::try_from(&body[42..46]).ok()?);
    let target = match kind {
        0 if body.len() == FIXED_LEN => Target::Archive(Format::Tar),
        1 if body.len() == FIXED_LEN => Target::Archive(Format::Zip),
        2 if body.len() >= FIXED_LEN + 2 => {
            let len = usize::from(u16::from_be_bytes([body[46], body[47]]));
            if len == 0 || len > MAX_PATH || body.len() != FIXED_LEN + 2 + len {
                return None;
            }
            Target::Entry(String::from_utf8(body[48..].to_vec()).ok()?)
        }
        _ => return None,
    };
    if token_epoch != epoch || now.0 >= expires_ms {
        return None;
    }
    Some(Link {
        tenant,
        artifact,
        target,
        expires_ms,
    })
}

fn tag_matches(expected: &[u8; TAG_LEN], presented: &[u8]) -> bool {
    if presented.len() != TAG_LEN {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(presented) {
        diff |= a ^ b;
    }
    core::hint::black_box(diff) == 0
}

/// What the access log keeps of a token: 64 bits of its digest, enough to correlate a redemption with the requester
/// that minted it and useless for spending it.
pub(crate) fn digest(token: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = blake3::hash(token.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &hash.as_bytes()[..8] {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> (tempfile::TempDir, Key) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        Key::create(&path).unwrap();
        let key = Key::load(&path).unwrap();
        (dir, key)
    }

    fn link(target: Target, expires_ms: i64) -> Link {
        Link {
            tenant: TenantId::new(),
            artifact: ArtifactId::new(),
            target,
            expires_ms,
        }
    }

    #[test]
    fn a_token_round_trips_and_its_expiry_is_exclusive() {
        let (_dir, key) = key();
        let epoch = key.active_id();
        for target in [
            Target::Archive(Format::Tar),
            Target::Archive(Format::Zip),
            Target::Entry("reports/out.txt".into()),
        ] {
            let link = link(target.clone(), 1_000);
            let token = mint(&key, &link, epoch);
            assert_eq!(
                verify(&key, &token, UnixMillis(999), epoch).as_ref(),
                Some(&link)
            );
            assert_eq!(verify(&key, &token, UnixMillis(1_000), epoch), None);
        }
    }

    #[test]
    fn a_forged_another_epoch_or_other_key_token_is_refused() {
        let (dir, key) = key();
        let epoch = key.active_id();
        let link = link(Target::Archive(Format::Tar), 1_000);
        let token = mint(&key, &link, epoch);
        assert!(verify(&key, &token, UnixMillis(1), epoch).is_some());
        assert_eq!(verify(&key, &token, UnixMillis(1), epoch + 1), None);

        let other = dir.path().join("other.key");
        Key::create(&other).unwrap();
        let other = Key::load(&other).unwrap();
        assert_eq!(
            verify(&other, &token, UnixMillis(1), other.active_id()),
            None
        );

        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        for damaged in [
            String::new(),
            token[..token.len() - 1].to_owned(),
            "not a token".to_owned(),
            {
                *bytes.last_mut().unwrap() ^= 1;
                URL_SAFE_NO_PAD.encode(&bytes)
            },
            {
                bytes.pop();
                URL_SAFE_NO_PAD.encode(&bytes)
            },
        ] {
            assert_ne!(damaged, token, "the damage must change the token");
            assert_eq!(
                verify(&key, &damaged, UnixMillis(1), epoch),
                None,
                "{damaged}"
            );
        }
    }

    #[test]
    fn a_token_names_one_entry_and_nothing_else() {
        let (_dir, key) = key();
        let epoch = key.active_id();
        let link = link(Target::Entry("build/app".into()), 1_000);
        let token = mint(&key, &link, epoch);
        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        // Rewriting the path or its length leaves the tag covering different bytes.
        let at = FIXED_LEN + 2;
        bytes[at] = b'B';
        assert_eq!(
            verify(&key, &URL_SAFE_NO_PAD.encode(&bytes), UnixMillis(1), epoch),
            None
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        bytes[FIXED_LEN + 1] -= 1;
        assert_eq!(
            verify(&key, &URL_SAFE_NO_PAD.encode(&bytes), UnixMillis(1), epoch),
            None
        );
        assert_eq!(
            verify(&key, &token, UnixMillis(1), epoch).unwrap().target,
            link.target
        );
    }

    #[test]
    fn the_access_log_value_is_a_digest_and_does_not_carry_the_token() {
        let (_dir, key) = key();
        let zip = mint(
            &key,
            &link(Target::Archive(Format::Zip), 1_000),
            key.active_id(),
        );
        let logged = digest(&zip);
        assert_eq!(logged.len(), 16);
        assert!(logged.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!logged.contains(&zip[..8]));
        let tar = mint(
            &key,
            &link(Target::Archive(Format::Tar), 1_000),
            key.active_id(),
        );
        assert_ne!(logged, digest(&tar));
    }
}
