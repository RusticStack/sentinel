//! W09: at-least-once delivery on the link. A controller that repeats an
//! offer — a retransmit after an uncertain send — gets it acknowledged
//! again, and the worker's executor is asked once: a duplicate offer never
//! becomes a duplicate execution within a healthy session. The controller
//! here is a hand-rolled session over the public `session` module, so the
//! duplicate can be sent on purpose.

use std::{
    net::TcpStream,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    AttemptId, Event, Fence, JobId, PoolId, RunId, TenantId, UnixMillis, WorkerId,
};
use sentinel_link::{
    identity::Identity,
    session::{
        self, Admission, Admitted, Beat, Capacity, Executor, JobContext, LogVerdict, Offer,
        Rejection, Reporter, SessionHandler,
    },
    tls,
};
use sentinel_protocol::{
    logs::Frame,
    negotiate::{Arch, Capabilities, Hello, ProtocolVersion},
};

struct FakeController {
    acks: Mutex<Vec<(AttemptId, Fence)>>,
}

impl Admission for FakeController {
    fn admit(
        &self,
        _: &Digest,
        worker: WorkerId,
        _: &str,
        hello: &Hello,
        _: Option<&Secret>,
        _: Capacity,
    ) -> Result<Admitted, Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        Ok(Admitted {
            worker,
            pool: PoolId::new(),
            negotiated,
        })
    }
}

impl SessionHandler for FakeController {
    fn ping(&self, _: WorkerId, _: &[AttemptId]) -> sentinel_link::Result<Beat> {
        Ok(Beat {
            lease_until: UnixMillis(i64::MAX / 2),
            stop: Vec::new(),
            cancel: Vec::new(),
        })
    }
    fn acknowledged(&self, _: WorkerId, attempt: AttemptId, fence: Fence) {
        self.acks.lock().unwrap().push((attempt, fence));
    }
    fn declined(&self, _: WorkerId, _: AttemptId, _: Fence) {}
    fn reported(&self, _: WorkerId, _: AttemptId, _: Fence, _: Event, _: Option<Vec<u8>>) {}
    fn spec(&self, _: WorkerId, _: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }
    fn log(&self, _: WorkerId, _: AttemptId, _: Frame) -> LogVerdict {
        LogVerdict::Refused
    }
    fn log_end(&self, _: WorkerId, _: AttemptId, _: u64, _: &[(u64, u64)]) {}
    fn abandoned(&self, _: WorkerId, _: AttemptId, _: Fence) {}
}

struct Counting {
    offered: Mutex<Vec<AttemptId>>,
}

impl Executor for Counting {
    fn offered(&self, offer: &Offer) -> bool {
        self.offered.lock().unwrap().push(offer.attempt);
        true
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.offered.lock().unwrap().clone()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, _: Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

#[test]
fn a_repeated_offer_is_acknowledged_twice_and_executed_once() {
    let controller = Arc::new(FakeController {
        acks: Mutex::new(Vec::new()),
    });
    let identity = Identity::generate("controller").unwrap();
    let fingerprint = identity.fingerprint();
    let config = tls::server_config(identity).unwrap();
    let listener = session::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let offer = Offer {
        attempt: AttemptId::new(),
        tenant: TenantId::new(),
        run: RunId::new(),
        job: JobId::new(),
        fence: Fence(1),
        lease_until: UnixMillis(i64::MAX / 2),
        cpu_millis: 1000,
        memory_bytes: 1 << 30,
        image_digest: "sha256:0".to_string(),
        image_platform: "linux/amd64".into(),
        job_index: 0,
    };
    let server = {
        let (controller, offer) = (Arc::clone(&controller), offer.clone());
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut s = session::accept(socket, config, &*controller).unwrap();
            let sender = s.sender();
            // The same offer, twice, then serve until the worker says goodbye.
            session::offer(&sender, &offer).unwrap();
            session::offer(&sender, &offer).unwrap();
            let _ = s.serve(&*controller);
        })
    };
    let worker = WorkerId::new();
    let client = tls::client_config(Identity::generate("worker").unwrap(), fingerprint).unwrap();
    let mut link = session::connect(
        addr,
        client,
        worker,
        "w",
        Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: ProtocolVersion(1),
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "test".into(),
        },
        None,
        Capacity {
            cpu_millis: 4000,
            memory_bytes: 4 << 30,
        },
    )
    .unwrap();
    let executor = Counting {
        offered: Mutex::new(Vec::new()),
    };
    // One beat handles whatever arrived: both offers and the pong.
    link.beat(&executor).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while controller.acks.lock().unwrap().len() < 2 {
        assert!(std::time::Instant::now() < deadline, "two acknowledgements");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        controller.acks.lock().unwrap().as_slice(),
        [(offer.attempt, Fence(1)), (offer.attempt, Fence(1))]
    );
    assert_eq!(executor.offered.lock().unwrap().as_slice(), [offer.attempt]);
    link.run(&executor, || true).unwrap();
    server.join().unwrap();
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(100));
}
