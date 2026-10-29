//! B05 harness: drives `restore::restore` and `publish::commit_profiled` exactly as a worker does,
//! on synthetic trees or on a real dependency/build tree, and prints one JSON record per cell.
//! Usage: see `bench/b05-cache.sh` and `docs/cache.md#measured-usefulness-b05`.

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
mod imp {
    use std::{
        collections::BTreeMap,
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::ExitCode,
        sync::{Barrier, Mutex},
        time::{Duration, Instant},
    };

    use sentinel_cache::{
        Attached, Backend, Outcome, Scope, Target, attach, clone,
        publish::{self, Phases, Published},
        restore::{self, Context},
    };
    use sentinel_core::{RepoId, TenantId, UnixMillis};
    use sentinel_pipeline::{expr::Template, schema::Cache};
    use sentinel_protocol::{
        cache::{Class, Trust},
        negotiate::Arch,
    };

    const MOUNT: &str = "/workspace";
    const PATH: &str = "deps";

    struct Args {
        work: PathBuf,
        out: Option<PathBuf>,
        label: String,
        shape: String,
        src: Option<PathBuf>,
        small: u64,
        small_bytes: u64,
        big: u64,
        big_bytes: u64,
        samples: usize,
        cold_samples: usize,
        dirty: Vec<u32>,
        threads: Vec<usize>,
        rounds: usize,
        force_copy: bool,
        modes: Vec<String>,
        keep: bool,
    }

    fn parse() -> Result<Args, String> {
        let mut a = Args {
            work: PathBuf::new(),
            out: None,
            label: String::new(),
            shape: "custom".into(),
            src: None,
            small: 0,
            small_bytes: 4096,
            big: 0,
            big_bytes: 0,
            samples: 5,
            cold_samples: 1,
            dirty: vec![0, 1, 10, 50],
            threads: Vec::new(),
            rounds: 8,
            force_copy: false,
            modes: vec!["lifecycle".into()],
            keep: false,
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            if matches!(k.as_str(), "--force-copy" | "--keep") {
                if k == "--keep" {
                    a.keep = true;
                } else {
                    a.force_copy = true;
                }
                continue;
            }
            let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
            let num = |v: &str| v.parse::<u64>().map_err(|_| format!("{k}: not a number"));
            let list = |v: &str| -> Result<Vec<u64>, String> {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().map_err(|_| format!("{k}: not a number list")))
                    .collect()
            };
            match k.as_str() {
                "--work" => a.work = PathBuf::from(v),
                "--out" => a.out = Some(PathBuf::from(v)),
                "--label" => a.label = v,
                "--shape" => a.shape = v,
                "--src" => a.src = Some(PathBuf::from(v)),
                "--small" => a.small = num(&v)?,
                "--small-bytes" => a.small_bytes = num(&v)?,
                "--big" => a.big = num(&v)?,
                "--big-bytes" => a.big_bytes = num(&v)?,
                "--samples" => a.samples = num(&v)? as usize,
                "--cold-samples" => a.cold_samples = num(&v)? as usize,
                "--dirty" => a.dirty = list(&v)?.into_iter().map(|n| n as u32).collect(),
                "--threads" => a.threads = list(&v)?.into_iter().map(|n| n as usize).collect(),
                "--rounds" => a.rounds = num(&v)? as usize,
                "--modes" => a.modes = v.split(',').map(str::to_owned).collect(),
                _ => return Err(format!("unknown flag {k}")),
            }
        }
        if a.work.as_os_str().is_empty() {
            return Err("--work is required".into());
        }
        Ok(a)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let n = self.next().to_le_bytes();
                chunk.copy_from_slice(&n[..chunk.len()]);
            }
        }
    }

    fn write_file(path: &Path, size: u64, seed: u64, mode: u32) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        let mut rng = Rng(seed | 1);
        let mut buf = vec![0u8; (1 << 20).min(size.max(1)) as usize];
        let mut left = size;
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            rng.fill(&mut buf[..n]);
            file.write_all(&buf[..n])?;
            left -= n as u64;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
    }

    fn rel_for(i: u64) -> String {
        format!(
            "d{:03}/d{:03}/d{:03}/f{i}",
            i / 65536 % 1000,
            i / 256 % 256,
            i % 256
        )
    }

    fn generate(dir: &Path, a: &Args) -> Result<(u64, u64), String> {
        let (mut files, mut bytes) = (0u64, 0u64);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut made = PathBuf::new();
        let mut one = |rel: String, size: u64, seed: u64| -> Result<(), String> {
            let path = dir.join(&rel);
            if let Some(parent) = path.parent()
                && made != parent
            {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                made = parent.to_path_buf();
            }
            let mode = if seed.is_multiple_of(7) { 0o755 } else { 0o644 };
            write_file(&path, size, seed, mode).map_err(|e| format!("{rel}: {e}"))?;
            files += 1;
            bytes += size;
            Ok(())
        };
        for i in 0..a.small {
            let scale = 1 + rng.next() % 16;
            let size = (a.small_bytes * scale / 4).max(1);
            one(rel_for(i), size, i + 1)?;
        }
        for i in 0..a.big {
            one(format!("big/b{i}.bin"), a.big_bytes, 1_000_000 + i)?;
        }
        Ok((files, bytes))
    }

    fn copy_tree(src: &Path, dst: &Path) -> Result<(u64, u64), String> {
        let (mut files, mut bytes) = (0u64, 0u64);
        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((from, to)) = stack.pop() {
            fs::create_dir_all(&to).map_err(|e| e.to_string())?;
            for entry in fs::read_dir(&from).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let ty = entry.file_type().map_err(|e| e.to_string())?;
                let target = to.join(entry.file_name());
                if ty.is_dir() {
                    stack.push((entry.path(), target));
                } else if ty.is_file() {
                    bytes += fs::copy(entry.path(), &target).map_err(|e| e.to_string())?;
                    files += 1;
                }
            }
        }
        Ok((files, bytes))
    }

    fn list_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            if let Ok(rd) = fs::read_dir(&d) {
                for e in rd.flatten() {
                    match e.file_type() {
                        Ok(t) if t.is_dir() => stack.push(e.path()),
                        Ok(t) if t.is_file() => out.push(e.path()),
                        _ => {}
                    }
                }
            }
        }
        out.sort();
        out
    }

    fn mutate(files: &[PathBuf], pct: u32, round: u64) -> Result<u64, String> {
        if pct == 0 || files.is_empty() {
            return Ok(0);
        }
        let step = (100 / pct.min(100)).max(1) as usize;
        let mut dirty = 0u64;
        for (i, path) in files.iter().enumerate().step_by(step) {
            let meta = fs::metadata(path).map_err(|e| e.to_string())?;
            let mode = {
                use std::os::unix::fs::MetadataExt;
                meta.mode() & 0o777
            };
            let tmp = path.with_extension("b05tmp");
            write_file(&tmp, meta.len(), (i as u64 + 1) * 1_000_003 + round, mode)
                .map_err(|e| e.to_string())?;
            fs::rename(&tmp, path).map_err(|e| e.to_string())?;
            dirty += meta.len();
        }
        Ok(dirty)
    }

    #[derive(Clone, Copy, Default)]
    struct Io {
        rchar: u64,
        wchar: u64,
        read_bytes: u64,
        write_bytes: u64,
        syscr: u64,
        syscw: u64,
    }

    fn io() -> Io {
        let mut out = Io::default();
        if let Ok(text) = fs::read_to_string("/proc/self/io") {
            for line in text.lines() {
                let Some((k, v)) = line.split_once(": ") else {
                    continue;
                };
                let v = v.trim().parse().unwrap_or(0);
                match k {
                    "rchar" => out.rchar = v,
                    "wchar" => out.wchar = v,
                    "read_bytes" => out.read_bytes = v,
                    "write_bytes" => out.write_bytes = v,
                    "syscr" => out.syscr = v,
                    "syscw" => out.syscw = v,
                    _ => {}
                }
            }
        }
        out
    }

    fn sub(a: Io, b: Io) -> Io {
        Io {
            rchar: a.rchar.saturating_sub(b.rchar),
            wchar: a.wchar.saturating_sub(b.wchar),
            read_bytes: a.read_bytes.saturating_sub(b.read_bytes),
            write_bytes: a.write_bytes.saturating_sub(b.write_bytes),
            syscr: a.syscr.saturating_sub(b.syscr),
            syscw: a.syscw.saturating_sub(b.syscw),
        }
    }

    fn syncfs(path: &Path) {
        if let Ok(f) = fs::File::open(path) {
            let _ = rustix::fs::syncfs(f);
        }
    }

    fn evict(dir: &Path) {
        use std::os::fd::AsRawFd;
        for path in list_files(dir) {
            if let Ok(f) = fs::File::open(&path) {
                // SAFETY: fd is open for the duration of the call; DONTNEED only drops clean cache pages.
                unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
            }
        }
    }

    #[derive(Default)]
    struct Dists(BTreeMap<String, Vec<u64>>);
    impl Dists {
        fn add(&mut self, name: &str, v: u64) {
            self.0.entry(name.to_owned()).or_default().push(v);
        }
        fn opt(&mut self, name: &str, v: Option<u64>) {
            if let Some(v) = v {
                self.add(name, v);
            }
        }
        fn json(&self) -> String {
            let mut s = String::from("{");
            for (i, (k, v)) in self.0.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let mut v = v.clone();
                v.sort_unstable();
                let n = v.len();
                let rank = |p: f64| v[(((p * n as f64).ceil() as usize).max(1) - 1).min(n - 1)];
                s.push_str(&format!(
                    "\"{k}\":{{\"n\":{n},\"min\":{},\"p50\":{},\"p95\":{},\"p99\":{},\"max\":{}}}",
                    v[0],
                    rank(0.50),
                    rank(0.95),
                    rank(0.99),
                    v[n - 1]
                ));
            }
            s.push('}');
            s
        }
    }

    fn q(s: &str) -> String {
        let mut o = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                c if (c as u32) < 0x20 => o.push(' '),
                c => o.push(c),
            }
        }
        o.push('"');
        o
    }

    fn host(work: &Path) -> String {
        let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
        let cpu = read("/proc/cpuinfo");
        let model = cpu
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split_once(": "))
            .map(|(_, v)| v.to_owned())
            .unwrap_or_default();
        let cpus = cpu.lines().filter(|l| l.starts_with("processor")).count();
        let mem = read("/proc/meminfo")
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        let kernel = read("/proc/sys/kernel/osrelease");
        let fs = std::process::Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(work)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        format!(
            "{{\"cpu\":{},\"vcpus\":{cpus},\"mem\":{},\"kernel\":{},\"fs\":{}}}",
            q(&model),
            q(mem.trim()),
            q(kernel.trim()),
            q(&fs)
        )
    }

    /// The build and host stamp from `B05_STAMP` (`bench/stamp.sh`); a record without it would name no
    /// commit and no host, so the run refuses to start.
    fn stamp() -> Result<String, String> {
        let stamp = std::env::var("B05_STAMP").unwrap_or_default();
        check_stamp(&stamp)?;
        Ok(stamp)
    }

    fn check_stamp(stamp: &str) -> Result<(), String> {
        // A non-empty string value for `key` inside the object `object` (`"build":{` or `"host":{`).
        let has = |object: &str, key: &str| {
            stamp.split_once(object).is_some_and(|(_, rest)| {
                rest.split_once(key)
                    .is_some_and(|(_, value)| !value.starts_with('"') && !value.is_empty())
            })
        };
        if has("\"build\":{", "\"commit\":\"") && has("\"host\":{", "\"hostname\":\"") {
            return Ok(());
        }
        Err(concat!(
            "B05_STAMP must hold the build and host stamp from bench/stamp.sh (a build commit and ",
            "a host label); run through bench/b05-cache.sh with SENTINEL_SRC and ",
            "SENTINEL_BENCH_HOST_LABEL set"
        )
        .into())
    }

    fn pressure() -> String {
        let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
        format!(
            "{{\"loadavg\":{},\"cpu\":{},\"io\":{}}}",
            q(read("/proc/loadavg").trim()),
            q(read("/proc/pressure/cpu").trim()),
            q(read("/proc/pressure/io").trim())
        )
    }

    struct Ctx<'a> {
        a: &'a Args,
        cache: PathBuf,
        backend: Backend,
        scope: Scope,
        decl: Cache,
        host: String,
        /// The `"build":{..},"host":{..}` fields the calling script stamped (`bench/stamp.sh`), spliced in verbatim.
        stamp: String,
        out: Mutex<Box<dyn Write + Send>>,
    }

    impl Ctx<'_> {
        fn env<'b>(&'b self, ws: &'b Path) -> Context<'b> {
            Context {
                cache_root: &self.cache,
                workspace: ws,
                workspace_mount: MOUNT,
                backend: self.backend,
            }
        }

        fn restore(&self, ws: &Path, key: &str, owner: &str) -> Attached {
            restore::restore(
                &self.env(ws),
                &self.decl,
                Some(key.to_owned()),
                self.scope.clone(),
                owner,
            )
        }

        fn commit(
            &self,
            at: &Attached,
            ph: &mut Phases,
        ) -> Result<Published, publish::PublishError> {
            publish::commit_profiled(
                &self.cache,
                at,
                Trust::Protected,
                UnixMillis(now_ms()),
                Instant::now() + Duration::from_secs(1800),
                &|| false,
                ph,
            )
        }

        fn emit(
            &self,
            kind: &str,
            start_state: &str,
            fields: &str,
            dists: &Dists,
        ) -> Result<(), String> {
            let stamp = &self.stamp;
            let line = format!(
                "{{\"record\":\"b05-{kind}\",\"label\":{},\"shape\":{},\"backend\":{},{stamp},\"hw\":{},\"load_start\":{start_state},\"load_end\":{},{fields},\"dist\":{}}}",
                q(&self.a.label),
                q(&self.a.shape),
                q(match self.backend {
                    Backend::Reflink => "reflink",
                    Backend::Copy => "copy",
                }),
                self.host,
                pressure(),
                dists.json()
            );
            let mut out = self
                .out
                .lock()
                .map_err(|_| "the record sink is poisoned".to_owned())?;
            writeln!(out, "{line}")
                .and_then(|()| out.flush())
                .map_err(|e| format!("cannot write the record: {e}"))
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn record_io(d: &mut Dists, prefix: &str, delta: Io) {
        d.add(&format!("{prefix}_rchar"), delta.rchar);
        d.add(&format!("{prefix}_wchar"), delta.wchar);
        d.add(&format!("{prefix}_read_bytes"), delta.read_bytes);
        d.add(&format!("{prefix}_write_bytes"), delta.write_bytes);
        d.add(&format!("{prefix}_syscalls"), delta.syscr + delta.syscw);
    }

    fn record_phases(d: &mut Dists, ph: &Phases) {
        d.add("lock_ns", ph.lock_ns);
        d.add("plan_ns", ph.plan_ns);
        d.add("materialize_ns", ph.materialize_ns);
        d.add("settle_ns", ph.settle_ns);
        d.add("seal_ns", ph.seal_ns);
    }

    fn attached_with_key(ctx: &Ctx<'_>, from: &Attached, key: &str) -> Attached {
        Attached {
            name: from.name.clone(),
            scope: from.scope.clone(),
            key: key.to_owned(),
            compat: attach::declared_compat(&ctx.decl, key, from.scope.platform),
            generation: None,
            outcome: Outcome::Miss(sentinel_cache::Miss::Absent),
            targets: from
                .targets
                .iter()
                .map(|t| Target {
                    declared: t.declared.clone(),
                    root: t.root.clone(),
                    dir: t.dir.clone(),
                    container: t.container.clone(),
                    mount: t.mount,
                })
                .collect(),
            lease: None,
            stats: Default::default(),
        }
    }

    fn published_label(p: &Result<Published, publish::PublishError>) -> String {
        match p {
            Ok(Published::Sealed { .. }) => "sealed".into(),
            Ok(Published::Skipped(r)) => r.as_str().into(),
            Err(e) => format!("error: {e}"),
        }
    }

    fn lifecycle(ctx: &Ctx<'_>) -> Result<(), String> {
        let a = ctx.a;
        let ws_root = a.work.join("ws");
        let seed = ws_root.join("seed");
        fs::create_dir_all(&seed).map_err(|e| e.to_string())?;
        let miss = ctx.restore(&seed, "k-cold-0", "seed");
        let dir = miss.targets[0].dir.clone();
        let t0 = Instant::now();
        let (files, bytes) = match &a.src {
            Some(src) => copy_tree(src, &dir)?,
            None => generate(&dir, a)?,
        };
        let gen_ns = t0.elapsed().as_nanos() as u64;
        syncfs(&dir);
        let shape = format!(
            "\"files\":{files},\"bytes\":{bytes},\"fixture_build_ns\":{gen_ns},\"samples\":{},\"cold_samples\":{}",
            a.samples, a.cold_samples
        );

        let mut d = Dists::default();
        let started = pressure();
        for i in 0..a.cold_samples {
            let at = attached_with_key(ctx, &miss, &format!("k-cold-{i}"));
            let (mut ph, before) = (Phases::default(), io());
            let t = Instant::now();
            let out = ctx.commit(&at, &mut ph);
            let wall = t.elapsed().as_nanos() as u64;
            let delta = sub(io(), before);
            if !matches!(out, Ok(Published::Sealed { .. })) {
                return Err(format!("cold publish {}", published_label(&out)));
            }
            d.add("wall_ns", wall);
            record_phases(&mut d, &ph);
            record_io(&mut d, "io", delta);
            d.add("write_amp_x1000", delta.write_bytes * 1000 / bytes.max(1));
            d.add("read_amp_x1000", delta.rchar * 1000 / bytes.max(1));
        }
        ctx.emit("cold-publish", &started, &shape, &d)?;
        drop(miss);

        let key = "k-cold-0";
        let gen_payload = {
            let entry = ctx
                .scope
                .entry_dir(&ctx.cache, attach::entry_key(Class::Dependencies, key));
            fs::read_to_string(entry.join("current"))
                .map(|g| entry.join(g.trim()).join("payload"))
                .map_err(|e| e.to_string())?
        };

        for (state, evicted) in [("page-cache-warm", false), ("fadvise-evicted", true)] {
            let mut d = Dists::default();
            let started = pressure();
            let mut copied_all = 0u64;
            for i in 0..a.samples {
                let ws = ws_root.join(format!("r{i}"));
                let _ = fs::remove_dir_all(&ws);
                fs::create_dir_all(&ws).map_err(|e| e.to_string())?;
                if evicted {
                    syncfs(&a.work);
                    evict(&gen_payload);
                }
                let before = io();
                let t = Instant::now();
                let at = ctx.restore(&ws, key, "r");
                let wall = t.elapsed().as_nanos() as u64;
                let delta = sub(io(), before);
                if !at.outcome.is_hit() {
                    return Err(format!("restore was not a hit: {:?}", at.outcome));
                }
                d.add("wall_ns", wall);
                d.opt("lookup_ns", at.stats.lookup_ns);
                d.opt("lock_wait_ns", at.stats.lock_wait_ns);
                d.opt("clone_ns", at.stats.clone_ns);
                d.opt("first_touch_ns", at.stats.first_touch_ns);
                d.add("copied_bytes", at.stats.copied_bytes);
                copied_all += u64::from(at.costly_hit().is_some());
                record_io(&mut d, "io", delta);
                d.add("write_amp_x1000", delta.write_bytes * 1000 / bytes.max(1));
                d.add("read_amp_x1000", delta.rchar * 1000 / bytes.max(1));
                drop(at);
                let _ = fs::remove_dir_all(&ws);
            }
            ctx.emit(
                "restore",
                &started,
                &format!(
                    "{shape},\"source_cache\":{},\"costly_flagged\":{copied_all}",
                    q(state)
                ),
                &d,
            )?;
        }

        let ws = ws_root.join("job");
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).map_err(|e| e.to_string())?;
        let mut at = ctx.restore(&ws, key, "job");
        if !at.outcome.is_hit() {
            return Err("job restore missed".into());
        }
        let job_files = list_files(&at.targets[0].dir);
        for &pct in &a.dirty {
            let mut d = Dists::default();
            let started = pressure();
            let mut outcomes: BTreeMap<String, u64> = BTreeMap::new();
            let mut dirty_logical = 0u64;
            for i in 0..a.samples {
                let t = Instant::now();
                let mut dirty = mutate(&job_files, pct, (pct as u64) << 16 | i as u64)?;
                if pct == 0 {
                    dirty = 0;
                }
                dirty_logical = dirty;
                d.add("mutate_ns", t.elapsed().as_nanos() as u64);
                let (mut ph, before) = (Phases::default(), io());
                let t = Instant::now();
                let out = ctx.commit(&at, &mut ph);
                let wall = t.elapsed().as_nanos() as u64;
                let delta = sub(io(), before);
                *outcomes.entry(published_label(&out)).or_default() += 1;
                d.add("wall_ns", wall);
                record_phases(&mut d, &ph);
                record_io(&mut d, "io", delta);
                if let Ok(Published::Sealed {
                    bytes: b,
                    reused_bytes: r,
                    ..
                }) = &out
                {
                    d.add("staged_bytes", *b);
                    d.add("reused_bytes", *r);
                    d.add("dirty_bytes", b - r);
                    d.add("write_amp_x1000", delta.write_bytes * 1000 / dirty.max(1));
                }
                d.add("read_amp_x1000", delta.rchar * 1000 / bytes.max(1));
                if let Ok(Published::Sealed { generation, .. }) = out {
                    at.generation = Some(generation);
                }
            }
            let outs: Vec<String> = outcomes
                .iter()
                .map(|(k, v)| format!("{}:{v}", q(k)))
                .collect();
            ctx.emit(
                "dirty-publish",
                &started,
                &format!(
                    "{shape},\"dirty_pct\":{pct},\"dirty_logical_bytes\":{dirty_logical},\"outcomes\":{{{}}}",
                    outs.join(",")
                ),
                &d,
            )?;
        }
        drop(at);
        Ok(())
    }

    fn concurrency(ctx: &Ctx<'_>) -> Result<(), String> {
        let a = ctx.a;
        let ws_root = a.work.join("ws");
        let seed = ws_root.join("cseed");
        fs::create_dir_all(&seed).map_err(|e| e.to_string())?;
        let miss = ctx.restore(&seed, "c-0", "seed");
        let dir = miss.targets[0].dir.clone();
        let (files, bytes) = match &a.src {
            Some(src) => copy_tree(src, &dir)?,
            None => generate(&dir, a)?,
        };
        syncfs(&dir);
        let max = a.threads.iter().copied().max().unwrap_or(1);
        for i in 0..max {
            let at = attached_with_key(ctx, &miss, &format!("c-{i}"));
            let mut ph = Phases::default();
            if !matches!(ctx.commit(&at, &mut ph), Ok(Published::Sealed { .. })) {
                return Err("seeding the concurrency entries failed".into());
            }
        }
        drop(miss);
        for &n in &a.threads {
            for distinct in [false, true] {
                let started = pressure();
                let barrier = Barrier::new(n);
                let sink: Mutex<Dists> = Mutex::new(Dists::default());
                let outcomes: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
                let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
                let t0 = Instant::now();
                std::thread::scope(|s| {
                    for t in 0..n {
                        let (barrier, sink, outcomes, errors) =
                            (&barrier, &sink, &outcomes, &errors);
                        let ws_root = &ws_root;
                        s.spawn(move || {
                            let key = if distinct {
                                format!("c-{t}")
                            } else {
                                "c-0".to_owned()
                            };
                            let ws = ws_root.join(format!("t{t}"));
                            for round in 0..a.rounds {
                                let _ = fs::remove_dir_all(&ws);
                                if fs::create_dir_all(&ws).is_err() {
                                    errors.lock().unwrap().push("ws".into());
                                    return;
                                }
                                barrier.wait();
                                let t1 = Instant::now();
                                let mut at = ctx.restore(&ws, &key, &format!("t{t}"));
                                let restore_ns = t1.elapsed().as_nanos() as u64;
                                if !at.outcome.is_hit() {
                                    errors
                                        .lock()
                                        .unwrap()
                                        .push(format!("miss {:?}", at.outcome));
                                    barrier.wait();
                                    continue;
                                }
                                let job = list_files(&at.targets[0].dir);
                                let _ = mutate(&job, 1, (t as u64) << 20 | round as u64);
                                barrier.wait();
                                let (mut ph, t2) = (Phases::default(), Instant::now());
                                let out = ctx.commit(&at, &mut ph);
                                let commit_ns = t2.elapsed().as_nanos() as u64;
                                if let Ok(Published::Sealed { generation, .. }) = &out {
                                    at.generation = Some(generation.clone());
                                }
                                let mut d = sink.lock().unwrap();
                                d.add("restore_ns", restore_ns);
                                d.opt("clone_ns", at.stats.clone_ns);
                                d.opt("lock_wait_ns", at.stats.lock_wait_ns);
                                d.opt("first_touch_ns", at.stats.first_touch_ns);
                                d.add("commit_ns", commit_ns);
                                if matches!(out, Ok(Published::Sealed { .. })) {
                                    d.add("commit_sealed_ns", commit_ns);
                                    d.add("sealed_plan_ns", ph.plan_ns);
                                    d.add("sealed_materialize_ns", ph.materialize_ns);
                                    d.add("sealed_settle_ns", ph.settle_ns);
                                }
                                drop(d);
                                *outcomes
                                    .lock()
                                    .unwrap()
                                    .entry(published_label(&out))
                                    .or_default() += 1;
                                drop(at);
                            }
                            let _ = fs::remove_dir_all(&ws);
                        });
                    }
                });
                let wall = t0.elapsed().as_nanos() as u64;
                let outs: Vec<String> = outcomes
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| format!("{}:{v}", q(k)))
                    .collect();
                let errs = errors.lock().unwrap().len();
                let d = sink.lock().unwrap();
                ctx.emit(
                    "concurrency",
                    &started,
                    &format!(
                        "\"files\":{files},\"bytes\":{bytes},\"threads\":{n},\"rounds\":{},\"entries\":{},\"wall_ns\":{wall},\"errors\":{errs},\"commit_outcomes\":{{{}}}",
                        a.rounds,
                        q(if distinct { "distinct" } else { "same" }),
                        outs.join(",")
                    ),
                    &d,
                )?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::check_stamp;

        const GOOD: &str = r#""build":{"commit":"0123456789abcdef0123456789abcdef01234567","dirty":false},"host":{"hostname":"reference-host","kernel":"6.1"}"#;

        #[test]
        fn a_stamped_run_starts() {
            assert!(check_stamp(GOOD).is_ok());
        }

        #[test]
        fn a_run_without_the_stamp_is_refused() {
            assert!(check_stamp("").is_err(), "unset B05_STAMP");
            assert!(
                check_stamp(r#""build":{"commit":"","dirty":false},"host":{}"#).is_err(),
                "an empty commit and no host label name nothing"
            );
            assert!(
                check_stamp(r#""build":{"commit":"abc"}"#).is_err(),
                "a build with no host label"
            );
            assert!(
                check_stamp(r#""host":{"hostname":"reference-host"}"#).is_err(),
                "a host with no build commit"
            );
        }
    }

    pub fn main() -> ExitCode {
        let a = match parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("b05-cache: {e}");
                return ExitCode::from(2);
            }
        };
        let stamp = match stamp() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("b05-cache: {e}");
                return ExitCode::from(2);
            }
        };
        let cache = a.work.join("cache");
        if let Err(e) = fs::create_dir_all(&cache) {
            eprintln!("b05-cache: {e}");
            return ExitCode::from(2);
        }
        let detected = clone::detect(&cache);
        let backend = if a.force_copy {
            Backend::Copy
        } else {
            detected
        };
        let scope = Scope::new(
            TenantId::new(),
            RepoId::new(),
            Class::Dependencies,
            Trust::Protected,
            sentinel_cache::Platform {
                os: sentinel_cache::Os::Linux,
                arch: Arch::X86_64,
            },
            Scope::toolchain_digest(b"b05"),
            "deps",
        )
        .expect("valid scope");
        let decl = Cache {
            name: "deps".into(),
            class: Class::Dependencies,
            key: Template::parse("b05").expect("template"),
            paths: vec![PATH.to_owned()],
        };
        let out: Box<dyn Write + Send> = match &a.out {
            Some(p) => match fs::OpenOptions::new().create(true).append(true).open(p) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    eprintln!("b05-cache: {e}");
                    return ExitCode::from(2);
                }
            },
            None => Box::new(std::io::stdout()),
        };
        let ctx = Ctx {
            host: host(&a.work),
            stamp,
            a: &a,
            cache,
            backend,
            scope,
            decl,
            out: Mutex::new(out),
        };
        let mut code = ExitCode::SUCCESS;
        for mode in &a.modes {
            let r = match mode.as_str() {
                "lifecycle" => lifecycle(&ctx),
                "concurrency" => concurrency(&ctx),
                other => Err(format!("unknown mode {other}")),
            };
            if let Err(e) = r {
                eprintln!("b05-cache: {mode}: {e}");
                code = ExitCode::from(1);
            }
        }
        if !a.keep {
            let _ = fs::remove_dir_all(a.work.join("ws"));
            let _ = fs::remove_dir_all(a.work.join("cache"));
        }
        code
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("b05-cache runs on Linux only");
}
