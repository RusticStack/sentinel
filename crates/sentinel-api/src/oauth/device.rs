//! The device authorization flow over HTTP (O03, RFC 8628): `POST
//! /oauth/device_authorization`, the device-code branch of the token
//! endpoint with its in-memory `slow_down` limiter, and the `GET`/`POST
//! /device` approval page ([`page`], in `device/page.rs`).
//!
//! The device code goes only to the polling client, in the JSON answer of
//! the authorization request; no page ever renders it. A person types the
//! user code on `/device` while signed in with a session.

#[path = "device/page.rs"]
mod page_impl;

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use sentinel_auth::oauth::{self as forms, Kind};
use sentinel_core::{
    UnixMillis,
    auth::{Audience, Scopes},
};
use sentinel_protocol::oauth::{DEVICE_VERIFICATION_PATH, DeviceAuthorization, OAuthErrorCode};
use sentinel_store::{
    Error as StoreError,
    oauth::{
        self as grants, Client, DEVICE_LIFETIME_MS, MAX_PENDING_DEVICE, SLOW_DOWN_STEP_MS,
        device::{self, Poll},
    },
};
use serde_json::json;

use super::{Form, error, error_status, store_failure, token_reply};
use crate::{
    State,
    http::Request,
    routes::{self, Reply, Route},
};

pub(crate) use page_impl::{WrongCodes, page};

/// `POST /oauth/device_authorization` (RFC 8628 §3.1): a public client asks
/// for a device code and a user code. `scope` defaults to the CLI default
/// within the client's ceiling; at the deployment's pending cap the answer
/// is `429 slow_down`.
pub(crate) fn authorization(state: &State, request: &mut Request) -> Route {
    Ok(authorize(state, request))
}

fn authorize(state: &State, request: &mut Request) -> Reply {
    if let Err(reply) = super::admit(state, request, super::Budget::Device) {
        return reply;
    }
    let form = match super::read_form(request) {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let Some(client_id) = form.get("client_id") else {
        return error(OAuthErrorCode::InvalidRequest, "client_id is required");
    };
    let client = match state.store.read(|c| grants::client(c, client_id)) {
        Ok(client) => client,
        Err(StoreError::NotFound) => return error(OAuthErrorCode::InvalidClient, "unknown client"),
        Err(e) => return store_failure(e),
    };
    if !client.device {
        return error(
            OAuthErrorCode::UnauthorizedClient,
            "this client may not use the device flow",
        );
    }
    let audience = match form.get("resource") {
        None => Audience::Api,
        Some(resource) => match state.oauth.resource_audience(resource) {
            Some(audience) => audience,
            None => return error(OAuthErrorCode::InvalidTarget, "resource is not served here"),
        },
    };
    let scopes = match form.get("scope").map(Scopes::parse) {
        None => Scopes::CLI_DEFAULT.intersect(client.max_scopes),
        Some(Ok(scopes)) => scopes,
        Some(Err(_)) => return error(OAuthErrorCode::InvalidScope, "unknown scope"),
    };
    if scopes.is_empty() || !client.max_scopes.contains(scopes) {
        return error(
            OAuthErrorCode::InvalidScope,
            "scope is empty or beyond what this client may ask for",
        );
    }
    let now = UnixMillis::now();
    let start = match device::begin(&state.store, &client.id, scopes, audience, now) {
        Ok(start) => start,
        Err(StoreError::QuotaExceeded) => {
            let mut reply = error_status(
                429,
                OAuthErrorCode::SlowDown,
                "too many pending device requests; retry later",
            );
            if let Reply::Json(_, _, headers) = &mut reply {
                headers.push(routes::header("retry-after", "5"));
            }
            return reply;
        }
        Err(StoreError::InvalidInput(_)) => {
            return error(OAuthErrorCode::InvalidScope, "scope is not allowed");
        }
        Err(StoreError::Forbidden) => {
            return error(
                OAuthErrorCode::UnauthorizedClient,
                "this client may not use the device flow",
            );
        }
        Err(StoreError::NotFound) => return error(OAuthErrorCode::InvalidClient, "unknown client"),
        Err(e) => return store_failure(e),
    };
    let verification_uri = format!("{}{DEVICE_VERIFICATION_PATH}", state.oauth.issuer);
    let body = DeviceAuthorization {
        device_code: forms::format(Kind::Device, &start.device),
        user_code: forms::display_user_code(&start.user_code),
        verification_uri_complete: format!("{verification_uri}?user_code={}", start.user_code),
        verification_uri,
        expires_in: u64::try_from(start.expires.0.saturating_sub(now.0) / 1000).unwrap_or(0),
        interval: u64::try_from(start.interval_ms / 1000).unwrap_or(5),
    };
    Reply::Json(200, json!(body), vec![routes::header("pragma", "no-cache")])
}

/// Ceiling on a device's polling interval: its whole life.
const MAX_INTERVAL_MS: u32 = DEVICE_LIFETIME_MS as u32;

/// Pace one poll of `key` at `now` (RFC 8628 §3.5). A device seen before
/// that polls sooner than its current interval is told to slow down and
/// its interval grows by [`SLOW_DOWN_STEP_MS`]; either way the poll time is
/// recorded. Devices not yet seen pass: only known pending requests are
/// remembered (see [`remember`]), so unknown codes cannot grow the map.
fn paced(polls: &mut HashMap<[u8; 32], (Instant, u32)>, key: &[u8; 32], now: Instant) -> bool {
    let Some((last, interval)) = polls.get_mut(key) else {
        return true;
    };
    let early = now.saturating_duration_since(*last) < Duration::from_millis(u64::from(*interval));
    *last = now;
    if early {
        *interval = interval
            .saturating_add(SLOW_DOWN_STEP_MS as u32)
            .min(MAX_INTERVAL_MS);
    }
    !early
}

/// Remember a pending request's poll at `now`, keeping its interval. The
/// map holds at most [`MAX_PENDING_DEVICE`] entries, which is also the
/// store's cap on pending requests; when full, entries idle for a whole
/// request life are dropped first, and if none is, this one goes unpaced.
fn remember(
    polls: &mut HashMap<[u8; 32], (Instant, u32)>,
    key: [u8; 32],
    now: Instant,
    initial_ms: u32,
) {
    if polls.len() >= MAX_PENDING_DEVICE && !polls.contains_key(&key) {
        let life = Duration::from_millis(DEVICE_LIFETIME_MS as u64);
        polls.retain(|_, (last, _)| now.saturating_duration_since(*last) < life);
        if polls.len() >= MAX_PENDING_DEVICE {
            return;
        }
    }
    polls
        .entry(key)
        .and_modify(|(last, _)| *last = now)
        .or_insert((now, initial_ms));
}

/// `grant_type=urn:ietf:params:oauth:grant-type:device_code` (RFC 8628
/// §3.4–3.5): `authorization_pending`, `slow_down`, `access_denied`,
/// `expired_token`, or the tokens exactly once; any later poll is
/// `invalid_grant`.
pub(crate) fn token(
    state: &State,
    client: &Client,
    form: &Form,
    resource: Option<Audience>,
) -> Reply {
    if !client.device {
        return error(
            OAuthErrorCode::UnauthorizedClient,
            "this client may not use the device flow",
        );
    }
    let Some(text) = form.get("device_code") else {
        return error(OAuthErrorCode::InvalidRequest, "device_code is required");
    };
    let Some(presented) = forms::parse(Kind::Device, text) else {
        return error(OAuthErrorCode::InvalidGrant, "device code is not valid");
    };
    let key = presented.digest().0;
    let polls = &state.oauth.device_polls;
    let lock = || polls.lock().unwrap_or_else(|p| p.into_inner());
    if !paced(&mut lock(), &key, Instant::now()) {
        return error(
            OAuthErrorCode::SlowDown,
            "polling too fast; add 5 seconds to the interval",
        );
    }
    let now = UnixMillis::now();
    let outcome = device::poll(&state.store, &client.id, &presented, resource, now);
    // A final answer ends pacing; a busy store is retried at the same pace.
    if matches!(
        outcome,
        Ok(Poll::Denied | Poll::Expired | Poll::Issued(_)) | Err(StoreError::NotFound)
    ) {
        lock().remove(&key);
    }
    match outcome {
        Ok(Poll::Pending) => {
            remember(
                &mut lock(),
                key,
                Instant::now(),
                grants::DEVICE_INTERVAL_MS as u32,
            );
            error(
                OAuthErrorCode::AuthorizationPending,
                "the request has not been approved yet",
            )
        }
        Ok(Poll::Denied) => error(OAuthErrorCode::AccessDenied, "the request was denied"),
        Ok(Poll::Expired) => error(OAuthErrorCode::ExpiredToken, "the device code expired"),
        Ok(Poll::Issued(minted)) => token_reply(&minted, now),
        Err(StoreError::NotFound) => {
            error(OAuthErrorCode::InvalidGrant, "device code is not valid")
        }
        Err(e) => store_failure(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_polls_slow_down_and_each_one_grows_the_interval() {
        let mut polls = HashMap::new();
        let key = [7u8; 32];
        let start = Instant::now();
        // Unknown devices pass and are not remembered by pacing alone.
        assert!(paced(&mut polls, &key, start));
        assert!(polls.is_empty());
        remember(&mut polls, key, start, 5_000);
        // 4.9 s later is early: slow down, interval 10 s.
        let t = start + Duration::from_millis(4_900);
        assert!(!paced(&mut polls, &key, t));
        assert_eq!(polls[&key].1, 10_000);
        // Waiting the old 5 s is still early now: 15 s.
        let t = t + Duration::from_millis(5_000);
        assert!(!paced(&mut polls, &key, t));
        assert_eq!(polls[&key].1, 15_000);
        // Honoring the grown interval passes and keeps it.
        let t = t + Duration::from_millis(15_000);
        assert!(paced(&mut polls, &key, t));
        assert_eq!(polls[&key].1, 15_000);
        remember(&mut polls, key, t, 5_000);
        assert_eq!(polls[&key].1, 15_000);
    }

    #[test]
    fn the_interval_is_capped_and_the_map_bounded() {
        let mut polls = HashMap::new();
        let start = Instant::now();
        let key = [1u8; 32];
        polls.insert(key, (start, MAX_INTERVAL_MS - 1));
        assert!(!paced(&mut polls, &key, start));
        assert_eq!(polls[&key].1, MAX_INTERVAL_MS);
        polls.clear();
        for n in 0..MAX_PENDING_DEVICE {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(n as u64).to_le_bytes());
            remember(&mut polls, k, start, 5_000);
        }
        // Full of live entries: a new one goes unremembered.
        remember(&mut polls, [0xff; 32], start, 5_000);
        assert_eq!(polls.len(), MAX_PENDING_DEVICE);
        assert!(!polls.contains_key(&[0xff; 32]));
        // Once they have idled a whole request life they make room.
        let later = start + Duration::from_millis(DEVICE_LIFETIME_MS as u64);
        remember(&mut polls, [0xff; 32], later, 5_000);
        assert_eq!(polls.len(), 1);
    }
}
