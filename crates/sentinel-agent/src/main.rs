//! The guest's `/init` for microVM jobs (plan 16.8, TODO M04).
//!
//! Boot: mount the job image (`/dev/vda`, read-only ext4) under a writable overlay on the attempt's scratch
//! disk (`/dev/vdb`), give it `/proc`, `/sys`, `/dev` and a 1 GiB `/tmp` as a container has, then serve
//! the worker on vsock port [`agent::PORT`]. Steps run as root chrooted into that overlay, each in its own
//! session; the VM is the boundary. As PID 1 the agent reaps every orphan, and one reaper thread reports a
//! step's end so an orphan reap can never swallow it.

#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("sentinel-agent runs only as a Linux guest's init");
        std::process::exit(2);
    }
}
