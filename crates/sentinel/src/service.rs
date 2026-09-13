use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::mpsc,
};

use serde::Deserialize;

use crate::cli::ServiceArgs;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

pub struct Error {
    pub code: u8,
    pub message: String,
}

impl Error {
    fn config(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    fn runtime(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    data_dir: Option<PathBuf>,
}

struct Config {
    data_dir: PathBuf,
}

impl Config {
    fn load(role: &str, args: &ServiceArgs) -> Result<Self, Error> {
        let file = match &args.config {
            Some(path) => read_config(path)?,
            None => FileConfig::default(),
        };
        let data_dir = args.data_dir.clone().or(file.data_dir).unwrap_or_else(|| {
            PathBuf::from(if role == "server" {
                "/var/lib/sentinel"
            } else {
                "/var/lib/sentinel-worker"
            })
        });
        if !data_dir.is_absolute()
            || !data_dir
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
            || data_dir
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(Error::config(
                "data_dir must be an absolute, non-root path without '..' components",
            ));
        }
        match fs::metadata(&data_dir) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(Error::config("data_dir exists but is not a directory"));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(Error::config(format!("cannot inspect data_dir: {error}")));
            }
            _ => {}
        }
        Ok(Self { data_dir })
    }
}

fn read_config(path: &Path) -> Result<FileConfig, Error> {
    if !fs::metadata(path)
        .map_err(|error| Error::config(format!("cannot inspect configuration file: {error}")))?
        .is_file()
    {
        return Err(Error::config("configuration must be a regular file"));
    }
    let file = File::open(path)
        .map_err(|error| Error::config(format!("cannot open configuration file: {error}")))?;
    if !file
        .metadata()
        .map_err(|error| Error::config(format!("cannot inspect configuration file: {error}")))?
        .is_file()
    {
        return Err(Error::config("configuration must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::config(format!("cannot read configuration file: {error}")))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::config("configuration exceeds the 64 KiB limit"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Error::config("configuration must be UTF-8"))?;
    // Parser diagnostics may echo arbitrary input, including accidentally pasted credentials.
    toml::from_str(text).map_err(|_| Error::config(
        "invalid configuration: expected strict TOML with only an optional string data_dir (no duplicate or unknown keys)",
    ))
}

pub fn run(role: &str, args: ServiceArgs) -> Result<(), Error> {
    let config = Config::load(role, &args)?;
    if args.check {
        println!(
            "{role} configuration valid; data_dir={}",
            config.data_dir.display()
        );
        return Ok(());
    }

    // Register before initialization so shutdown requested during startup is retained.
    // Signal callbacks only enqueue; cleanup and reporting stay on the main thread.
    let (sender, receiver) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = sender.try_send(());
    })
    .map_err(|error| Error::runtime(format!("cannot install shutdown handler: {error}")))?;
    fs::create_dir_all(&config.data_dir)
        .map_err(|error| Error::runtime(format!("cannot initialize data_dir: {error}")))?;

    eprintln!(
        "sentinel {} {role} initialized; data_dir={}; lifecycle only, CI services are not implemented",
        env!("CARGO_PKG_VERSION"),
        config.data_dir.display()
    );
    receiver
        .recv()
        .map_err(|_| Error::runtime("shutdown channel disconnected"))?;
    // No jobs, listeners, or persistent writers exist yet. Their bounded drain/flush
    // operations must be added here as the corresponding subsystems are implemented.
    eprintln!("{role} shutdown requested");
    eprintln!("{role} stopped");
    Ok(())
}
