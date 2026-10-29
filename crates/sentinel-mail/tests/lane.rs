use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{UnixMillis, UserId};
use sentinel_mail::{Failure, Lane, LaneConfig, Mail, Transport};
use sentinel_store::{Durability, Store, email, local_auth};

type Sent = Arc<Mutex<Vec<(String, String)>>>;

struct Scripted {
    outcomes: VecDeque<Result<(), Failure>>,
    sent: Sent,
}

impl Transport for Scripted {
    fn send(&mut self, mail: &Mail<'_>) -> Result<(), Failure> {
        self.sent
            .lock()
            .unwrap()
            .push((mail.to.to_owned(), mail.body.to_owned()));
        self.outcomes.pop_front().unwrap_or(Ok(()))
    }
}

struct World {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    key: Arc<Key>,
    user: UserId,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let user = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"an operator password",
        UnixMillis(0),
    )
    .unwrap();
    let path = dir.path().join("master.key");
    Key::create(&path).unwrap();
    let key = Arc::new(Key::load(&path).unwrap());
    email::set_delivery(&store, true, Some("https://ci.example.com"), UnixMillis(1)).unwrap();
    World {
        _dir: dir,
        store,
        key,
        user,
    }
}

impl World {
    fn queue(&self, address: &'static str) {
        let (key, user) = (Arc::clone(&self.key), self.user);
        let outcome = self
            .store
            .writer()
            .write(move |tx| email::request(tx, Some(&key), user, address, None, UnixMillis::now()))
            .unwrap();
        assert_eq!(outcome, email::Requested::Queued);
    }

    fn counts(&self) -> (i64, i64, i64) {
        self.store.read(email::counts).unwrap()
    }

    fn start(&self, key: Arc<Key>, outcomes: Vec<Result<(), Failure>>) -> (Lane, Sent) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = Scripted {
            outcomes: outcomes.into(),
            sent: Arc::clone(&sent),
        };
        let lane = Lane::start(
            Arc::clone(&self.store),
            key,
            Box::new(transport),
            LaneConfig {
                batch: 8,
                idle: Duration::from_millis(100),
                min_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(50),
                maintenance: Duration::from_secs(3600),
            },
            |_| {},
        );
        (lane, sent)
    }
}

fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn a_queued_message_is_delivered_once_and_loses_its_body() {
    let w = world();
    w.queue("guest@example.com");
    let (lane, sent) = w.start(Arc::clone(&w.key), vec![Ok(())]);
    eventually("the message to settle", || w.counts() == (0, 1, 0));
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 1, "one message, one send");
    assert_eq!(sent[0].0, "guest@example.com");
    assert!(
        sent[0]
            .1
            .contains("https://ci.example.com/verify-email#token=")
    );
    drop(sent);
    drop(lane);
}

#[test]
fn a_transient_failure_waits_for_its_backoff_instead_of_spinning() {
    let w = world();
    w.queue("slow@example.com");
    let (lane, sent) = w.start(
        Arc::clone(&w.key),
        vec![Err(Failure::transient("resend unreachable"))],
    );
    eventually("the first attempt", || !sent.lock().unwrap().is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        sent.lock().unwrap().len(),
        1,
        "retried only after the store's backoff"
    );
    assert_eq!(w.counts(), (1, 0, 0), "still pending, not abandoned");
    let next = w.store.read(email::next_due_ms).unwrap().unwrap();
    assert!(
        next >= UnixMillis::now().0 + 30_000,
        "scheduled well into the future"
    );
    drop(lane);
}

#[test]
fn a_throttled_message_waits_for_the_retry_after_the_service_gave() {
    let w = world();
    w.queue("throttled@example.com");
    let (lane, sent) = w.start(
        Arc::clone(&w.key),
        vec![Err(Failure::Transient {
            why: "resend throttled the request (429)".into(),
            retry_after: Some(Duration::from_secs(600)),
        })],
    );
    eventually("the first attempt", || !sent.lock().unwrap().is_empty());
    eventually("the retry to be scheduled", || {
        w.store
            .read(email::next_due_ms)
            .unwrap()
            .is_some_and(|next| next >= UnixMillis::now().0 + 590_000)
    });
    assert_eq!(w.counts(), (1, 0, 0), "pending, not abandoned");
    drop(lane);
}

#[test]
fn a_refused_message_is_given_up_and_not_retried() {
    let w = world();
    w.queue("nobody@example.com");
    let (lane, sent) = w.start(
        Arc::clone(&w.key),
        vec![Err(Failure::Permanent(
            "resend refused the message (422)".into(),
        ))],
    );
    eventually("the message to be given up", || w.counts() == (0, 0, 1));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(sent.lock().unwrap().len(), 1);
    drop(lane);
}

#[test]
fn a_message_the_lane_cannot_open_never_reaches_the_relay() {
    let w = world();
    w.queue("sealed@example.com");
    let other = tempfile::tempdir().unwrap();
    let path = other.path().join("master.key");
    Key::create(&path).unwrap();
    let wrong = Arc::new(Key::load(&path).unwrap());
    let (lane, sent) = w.start(wrong, vec![]);
    eventually("the message to be given up", || w.counts() == (0, 0, 1));
    assert!(sent.lock().unwrap().is_empty(), "nothing was sent");
    drop(lane);
}

#[test]
fn dropping_the_lane_stops_it_promptly() {
    let w = world();
    let (lane, _) = w.start(Arc::clone(&w.key), vec![]);
    let started = Instant::now();
    drop(lane);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_delivered_message_still_counts_against_its_mailbox_allowance() {
    let w = world();
    w.queue("guest@example.com");
    let (lane, _sent) = w.start(Arc::clone(&w.key), vec![Ok(())]);
    eventually("the message to settle", || w.counts() == (0, 1, 0));
    drop(lane);

    let (key, user) = (Arc::clone(&w.key), w.user);
    let again = w
        .store
        .writer()
        .write(move |tx| {
            email::request(
                tx,
                Some(&key),
                user,
                "guest@example.com",
                None,
                UnixMillis::now(),
            )
        })
        .unwrap();
    assert_eq!(
        again,
        email::Requested::Throttled,
        "delivery does not reset the cooldown"
    );
    assert_eq!(w.counts(), (0, 1, 0), "nothing new was queued");
}
