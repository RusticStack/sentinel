//! The shipped example configurations and deployment files must keep working against the real
//! binary: the TOML files go through the real parser (`--check`), and every flag the units and
//! container files pass to `sentinel` must exist in that role's `--help`.
#![cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]

use sentinel_pipeline::yaml::{self, Node};
use std::{fs, path::PathBuf, process::Command};

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

fn sentinel(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .expect("run sentinel")
}

fn enabled(role: &str) -> bool {
    match role {
        "server" => cfg!(feature = "server"),
        _ => cfg!(feature = "worker"),
    }
}

/// Checks `text` as a configuration for `role` and returns the diagnostic on failure.
fn check(role: &str, text: &str) -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    fs::write(&file, text).unwrap();
    let output = sentinel(&[role, "--config", file.to_str().unwrap(), "--check"]);
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Removes the leading `# ` from lines that are commented-out settings (`# key = value`,
/// `# [table]`), leaving prose comments alone.
fn enable_commented_settings(text: &str) -> String {
    text.lines()
        .map(|line| {
            let Some(rest) = line.strip_prefix("# ") else {
                return line.to_owned();
            };
            let key = rest.split([' ', '=']).next().unwrap_or("");
            let setting = rest.contains(" = ")
                && !key.is_empty()
                && key.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            let table = rest.starts_with('[') && rest.trim_end().ends_with(']');
            if setting || table {
                rest.to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn example_configurations_load_through_the_real_parser() {
    for (file, role) in [
        ("server.toml", "server"),
        ("server-container.toml", "server"),
        ("worker.toml", "worker"),
    ] {
        if !enabled(role) {
            continue;
        }
        let text = fs::read_to_string(example(file)).unwrap();
        if let Err(error) = check(role, &text) {
            panic!("examples/{file} is rejected: {error}");
        }
    }
}

#[test]
fn every_commented_setting_in_the_examples_is_a_known_key() {
    // Uncommenting a setting must not hit an unknown key or a type error. Settings that exclude
    // each other (Tailcat versus direct TLS) are not combined by the examples, so a semantic
    // refusal is the only failure tolerated, and it must not be the generic parse error.
    for (file, role) in [("server.toml", "server"), ("worker.toml", "worker")] {
        if !enabled(role) {
            continue;
        }
        let text = enable_commented_settings(&fs::read_to_string(example(file)).unwrap());
        if let Err(error) = check(role, &text) {
            assert!(
                !error.contains("invalid configuration"),
                "examples/{file} has a commented setting the parser rejects: {error}"
            );
        }
    }
}

/// The `--flags` that appear in `words`, a command line after the role name.
fn flags(words: &[String]) -> Vec<String> {
    words
        .iter()
        .filter(|word| word.starts_with("--"))
        .map(|word| word.split('=').next().unwrap().to_owned())
        .collect()
}

fn assert_flags_exist(origin: &str, words: &[String]) {
    let Some(at) = words
        .iter()
        .position(|word| word == "server" || word == "worker")
    else {
        panic!("{origin}: no role in {words:?}");
    };
    let role = words[at].as_str();
    if !enabled(role) {
        return;
    }
    let help = String::from_utf8_lossy(&sentinel(&[role, "--help"]).stdout).into_owned();
    for flag in flags(&words[at + 1..]) {
        assert!(
            help.contains(&flag),
            "{origin}: `sentinel {role}` has no {flag} flag"
        );
    }
}

#[test]
fn unit_and_container_command_lines_use_flags_that_exist() {
    let mut seen = 0;
    for name in ["sentinel-server.service", "sentinel-worker.service"] {
        let text = fs::read_to_string(example(name)).unwrap();
        for line in text.lines() {
            let Some(command) = line.strip_prefix("ExecStart=") else {
                continue;
            };
            let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            assert!(words[0].ends_with("/sentinel"), "{name}: {command}");
            assert_flags_exist(name, &words);
            seen += 1;
        }
    }
    for name in [
        "compose.server.yaml",
        "compose.worker.yaml",
        "Containerfile.server",
        "Containerfile.worker",
    ] {
        let text = fs::read_to_string(example(name)).unwrap();
        for line in text.lines() {
            let line = line.trim();
            let list = line
                .strip_prefix("command:")
                .or_else(|| line.strip_prefix("CMD"))
                .map(str::trim);
            let Some(list) = list.filter(|list| list.starts_with('[')) else {
                continue;
            };
            let words: Vec<String> = list
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|word| word.trim().trim_matches('"').to_owned())
                .collect();
            // Health checks and other lists are not the service's command line.
            if words
                .iter()
                .any(|word| word == "server" || word == "worker")
            {
                assert_flags_exist(name, &words);
                seen += 1;
            }
        }
    }
    assert_eq!(
        seen, 6,
        "expected two units and four container command lines"
    );
}

#[test]
fn worker_check_names_every_missing_microvm_piece() {
    if !enabled("worker") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().display();
    let config = dir.path().join("worker.toml");
    fs::write(
        &config,
        format!(
            "data_dir = \"{root}/data\"\ncontroller = \"10.0.0.5:7443\"\ncontroller_fingerprint = \"{}\"\n\n[microvm]\nfirecracker = \"{root}/firecracker\"\nkernel = \"{root}/vmlinux\"\nagent = \"{root}/sentinel-agent\"\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    fs::create_dir(dir.path().join("data")).unwrap();
    let output = sentinel(&["worker", "--config", config.to_str().unwrap(), "--check"]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("microvm=unavailable"), "{text}");
    assert!(text.contains("firecracker "), "{text}");
    assert!(text.contains("vmlinux: no guest kernel"), "{text}");
    assert!(text.contains("agent "), "{text}");
    assert!(text.contains("docs/releasing.md#microvm-assets"), "{text}");
}

// The web interface beside the controller (examples/compose.server.yaml, the Quadlet files and
// Containerfile.web). The checks are pure functions of the file texts so that the failure-path
// tests can feed them altered copies.

/// The node at a dotted `path` of mapping keys.
fn at<'a>(node: &'a Node, path: &str) -> Option<&'a Node> {
    path.split('.').try_fold(node, |node, key| node.get(key))
}

fn scalar(node: &Node) -> Option<String> {
    match node {
        Node::Str(text) => Some(text.clone()),
        Node::Int(number) => Some(number.to_string()),
        Node::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn strings(node: Option<&Node>) -> Vec<String> {
    match node {
        Some(Node::Seq(items)) => items.iter().filter_map(scalar).collect(),
        _ => Vec::new(),
    }
}

fn keys(node: Option<&Node>) -> Vec<&str> {
    match node {
        Some(Node::Map(entries)) => entries.iter().map(|(key, _)| key.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn value(node: &Node, path: &str) -> Option<String> {
    at(node, path).and_then(scalar)
}

fn read(name: &str) -> String {
    fs::read_to_string(example(name)).unwrap_or_else(|error| panic!("examples/{name}: {error}"))
}

fn repo_file(path: &str) -> String {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path);
    fs::read_to_string(&file).unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn parse_compose(text: &str) -> Result<Node, String> {
    yaml::load(text).map_err(|error| format!("compose file is not valid YAML: {error}"))
}

fn ipv4(text: &str) -> Option<u32> {
    let mut address = 0u32;
    let mut parts = 0;
    for part in text.split('.') {
        address = (address << 8) | u32::from(part.parse::<u8>().ok()?);
        parts += 1;
    }
    (parts == 4).then_some(address)
}

fn in_subnet(address: &str, cidr: &str) -> bool {
    let inside = || {
        let (network, bits) = cidr.split_once('/')?;
        let bits: u32 = bits.parse().ok().filter(|bits| *bits <= 32)?;
        let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
        Some(ipv4(address)? & mask == ipv4(network)? & mask)
    };
    inside().unwrap_or(false)
}

/// `$NAME` and `${NAME...}` references outside comment lines (`$$` is a literal dollar sign).
fn variables(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        let mut rest = line;
        while let Some(at) = rest.find('$') {
            rest = &rest[at + 1..];
            if let Some(after) = rest.strip_prefix('$') {
                rest = after;
                continue;
            }
            let body = rest.strip_prefix('{').unwrap_or(rest);
            let name: String = body
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                found.push(name);
            }
        }
    }
    found
}

const SECRET_WORDS: [&str; 6] = ["secret", "token", "passw", "credential", "private", "key"];

/// What every Compose file here must satisfy: no credential in it, and no variable but the version.
fn check_compose_hygiene(text: &str) -> Result<(), String> {
    let compose = parse_compose(text)?;
    for name in variables(text) {
        if name != "SENTINEL_VERSION" {
            return Err(format!("variable `{name}` is not defined by the examples"));
        }
    }
    for service in keys(at(&compose, "services")) {
        let Some(node) = at(&compose, "services").and_then(|services| services.get(service)) else {
            return Err(format!("service `{service}` is missing"));
        };
        for forbidden in ["env_file", "secrets"] {
            if node.get(forbidden).is_some() {
                return Err(format!("service `{service}` sets `{forbidden}`"));
            }
        }
        for name in keys(node.get("environment")) {
            let lower = name.to_ascii_lowercase();
            if SECRET_WORDS.iter().any(|word| lower.contains(word)) {
                return Err(format!(
                    "service `{service}` sets `{name}`, which looks like a credential"
                ));
            }
        }
    }
    Ok(())
}

/// The environment of the `web` service: the names `sentinel-web` reads, plus what Node and the
/// listener need.
const WEB_ENVIRONMENT: [&str; 6] = [
    "NODE_ENV",
    "HOST",
    "PORT",
    "SENTINEL_API",
    "SENTINEL_CLIENT_IP_HEADER",
    "SENTINEL_GITHUB_WEB_URL",
];

/// Keys that would widen the service beyond the hardened baseline or hand it state.
const WEB_FORBIDDEN: [&str; 11] = [
    "build",
    "cap_add",
    "devices",
    "env_file",
    "ipc",
    "network_mode",
    "pid",
    "privileged",
    "secrets",
    "user",
    "volumes",
];

fn check_ports(service: &str, node: &Node) -> Result<Vec<String>, String> {
    let ports = strings(node.get("ports"));
    for port in &ports {
        if !port.starts_with("127.0.0.1:") {
            return Err(format!(
                "service `{service}` publishes `{port}`: ports bind 127.0.0.1 only"
            ));
        }
    }
    Ok(ports)
}

/// The `web` service of `compose.server.yaml` against the controller configuration it is run
/// with (`server_toml`): hardened like the controller, loopback only, started after a healthy
/// controller, pointed at the controller's API, and trusted by it as a proxy by its fixed address.
fn check_web_service(compose_text: &str, server_toml: &str) -> Result<(), String> {
    check_compose_hygiene(compose_text)?;
    let compose = parse_compose(compose_text)?;
    let server = at(&compose, "services.server").ok_or("no `server` service")?;
    let web = at(&compose, "services.web").ok_or("no `web` service")?;

    let image = value(web, "image").ok_or("web has no image")?;
    let server_image = value(server, "image").ok_or("server has no image")?;
    let tag = server_image
        .strip_prefix("localhost/sentinel-server:")
        .ok_or("server image is not localhost/sentinel-server:<tag>")?;
    if image != format!("localhost/sentinel-web:{tag}") {
        return Err(format!(
            "web image `{image}` is not localhost/sentinel-web with the controller's tag `{tag}`"
        ));
    }
    for key in WEB_FORBIDDEN {
        if web.get(key).is_some() {
            return Err(format!("web sets `{key}`"));
        }
    }
    if strings(web.get("profiles")) != ["web"] {
        return Err("web must be in the `web` profile only".into());
    }
    if value(web, "depends_on.server.condition").as_deref() != Some("service_healthy") {
        return Err("web must depend on server with condition service_healthy".into());
    }
    for key in ["restart", "stop_grace_period", "mem_limit"] {
        if web.get(key).is_none() {
            return Err(format!("web sets no `{key}`"));
        }
    }
    if !matches!(web.get("pids_limit"), Some(Node::Int(limit)) if *limit > 0) {
        return Err("web sets no pids_limit".into());
    }
    if web.get("read_only") != Some(&Node::Bool(true)) {
        return Err("web does not set read_only: true".into());
    }
    if strings(web.get("cap_drop")) != ["ALL"] {
        return Err("web does not drop ALL capabilities".into());
    }
    if !strings(web.get("security_opt")).contains(&"no-new-privileges:true".to_owned()) {
        return Err("web does not set no-new-privileges".into());
    }
    if !strings(web.get("tmpfs"))
        .iter()
        .any(|mount| mount.starts_with("/tmp:") && mount.contains("size="))
    {
        return Err("web has no size-bounded tmpfs on /tmp".into());
    }

    let environment = web.get("environment");
    for name in keys(environment) {
        if !WEB_ENVIRONMENT.contains(&name) {
            return Err(format!(
                "web sets `{name}`, which sentinel-web does not read"
            ));
        }
    }
    let env = |name: &str| environment.and_then(|env| env.get(name)).and_then(scalar);
    if env("HOST").as_deref() != Some("0.0.0.0") {
        return Err("web must listen on 0.0.0.0 inside its container".into());
    }
    let port = env("PORT").ok_or("web sets no PORT")?;
    let published = check_ports("web", web)?;
    if published != [format!("127.0.0.1:{port}:{port}")] {
        return Err(format!(
            "web must publish exactly 127.0.0.1:{port}:{port}, not {published:?}"
        ));
    }
    check_ports("server", server)?;

    let server_config: toml::Table = server_toml
        .parse()
        .map_err(|_| "server-container.toml is not TOML".to_owned())?;
    let api_port = server_config
        .get("api_listen")
        .and_then(toml::Value::as_str)
        .and_then(|listen| listen.rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .ok_or("server-container.toml has no api_listen")?;
    let api = env("SENTINEL_API").ok_or("web sets no SENTINEL_API")?;
    let authority = api
        .strip_prefix("http://")
        .ok_or_else(|| format!("SENTINEL_API `{api}` is not plain http://<service>:<port>"))?;
    let (host, api_target) = authority
        .split_once(':')
        .ok_or_else(|| format!("SENTINEL_API `{api}` has no port"))?;
    if !keys(at(&compose, "services")).contains(&host) {
        return Err(format!(
            "SENTINEL_API names `{host}`, which is not a service"
        ));
    }
    if api_target != api_port {
        return Err(format!(
            "SENTINEL_API port {api_target} is not the controller's api_listen port {api_port}"
        ));
    }

    let subnet = at(&compose, "networks.default.ipam.config")
        .and_then(|config| match config {
            Node::Seq(items) => items.first(),
            _ => None,
        })
        .and_then(|entry| value(entry, "subnet"))
        .ok_or("the default network has no pinned subnet")?;
    let address = value(web, "networks.default.ipv4_address").ok_or("web has no fixed address")?;
    if !in_subnet(&address, &subnet) {
        return Err(format!(
            "web address {address} is outside the subnet {subnet}"
        ));
    }
    let trusted: Vec<String> = server_config
        .get("trusted_proxies")
        .and_then(toml::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if trusted != [address.as_str()] {
        return Err(format!(
            "trusted_proxies {trusted:?} is not exactly web's address {address}, so every browser would share one rate-limit allowance"
        ));
    }
    Ok(())
}

#[test]
fn compose_server_defines_a_hardened_web_service() {
    check_web_service(&read("compose.server.yaml"), &read("server-container.toml"))
        .unwrap_or_else(|error| panic!("examples/compose.server.yaml: {error}"));
}

#[test]
fn compose_files_hold_no_credentials_and_no_unknown_variables() {
    for name in ["compose.server.yaml", "compose.worker.yaml"] {
        check_compose_hygiene(&read(name))
            .unwrap_or_else(|error| panic!("examples/{name}: {error}"));
    }
}

/// Every `.ts` and `.tsx` source under `dir`, concatenated.
fn web_sources(dir: &std::path::Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            web_sources(&path, out);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("ts" | "tsx")
        ) {
            out.push_str(&fs::read_to_string(&path).unwrap_or_default());
        }
    }
}

#[test]
fn every_setting_the_web_examples_set_is_read_by_sentinel_web() {
    let mut sources = String::new();
    web_sources(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web/src"),
        &mut sources,
    );
    assert!(sources.contains("SENTINEL_API"), "web/src was not read");
    for file in [
        "compose.server.yaml",
        "sentinel-web.service",
        "sentinel-web.container",
    ] {
        let text = read(file);
        let mut rest = text.as_str();
        while let Some(at) = rest.find("SENTINEL_") {
            let name: String = rest[at..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            rest = &rest[at + name.len()..];
            // The image tag variable belongs to Compose, not to the web process.
            if name == "SENTINEL_VERSION" {
                continue;
            }
            assert!(
                sources.contains(&name),
                "examples/{file} sets {name}, which web/src never reads"
            );
        }
    }
}

/// `Key=value` lines of a Quadlet file, in order.
fn quadlet(name: &str) -> Vec<(String, String)> {
    read(name)
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn quadlet_values<'a>(lines: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    lines
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
fn quadlet_and_compose_describe_the_same_web_deployment() {
    let compose = parse_compose(&read("compose.server.yaml")).unwrap();
    let web = at(&compose, "services.web").unwrap();
    let toml = read("server-container.toml");
    let subnet = match at(&compose, "networks.default.ipam.config") {
        Some(Node::Seq(items)) => value(&items[0], "subnet").unwrap(),
        other => panic!("no pinned subnet: {other:?}"),
    };
    let address = value(web, "networks.default.ipv4_address").unwrap();

    let network = quadlet("sentinel.network");
    assert_eq!(quadlet_values(&network, "Subnet"), [subnet.as_str()]);
    let gateway = quadlet_values(&network, "Gateway");
    assert!(
        gateway.len() == 1 && in_subnet(gateway[0], &subnet) && gateway[0] != address,
        "gateway {gateway:?} must be another address inside {subnet}"
    );

    let unit = quadlet("sentinel-web.container");
    let server = quadlet("sentinel-server.container");
    assert_eq!(quadlet_values(&unit, "IP"), [address.as_str()]);
    for lines in [&unit, &server] {
        assert_eq!(quadlet_values(lines, "Network"), ["sentinel.network"]);
    }
    assert!(toml.contains(&format!("trusted_proxies = [\"{address}\"]")));
    assert_eq!(
        quadlet_values(&unit, "Requires"),
        ["sentinel-server.service"]
    );

    // The same tag, loopback-only publication, hardening and port as the Compose service.
    let tag = |lines: &[(String, String)], image: &str| {
        quadlet_values(lines, "Image")
            .first()
            .and_then(|value| value.strip_prefix(image))
            .map(str::to_owned)
    };
    let web_tag = tag(&unit, "localhost/sentinel-web:");
    assert!(web_tag.is_some());
    assert_eq!(web_tag, tag(&server, "localhost/sentinel-server:"));
    assert_eq!(
        quadlet_values(&unit, "PublishPort"),
        ["127.0.0.1:3000:3000"]
    );
    assert_eq!(quadlet_values(&unit, "ReadOnly"), ["true"]);
    assert_eq!(quadlet_values(&unit, "DropCapability"), ["ALL"]);
    assert_eq!(quadlet_values(&unit, "NoNewPrivileges"), ["true"]);
    assert_eq!(quadlet_values(&unit, "PidsLimit"), ["256"]);
    assert_eq!(
        quadlet_values(&server, "ContainerName"),
        ["sentinel-server"]
    );
    let environment = quadlet_values(&unit, "Environment");
    assert!(
        environment.contains(&"SENTINEL_API=http://sentinel-server:7080"),
        "{environment:?}"
    );
    assert!(environment.contains(&"PORT=3000"), "{environment:?}");
    for setting in &environment {
        let name = setting.split('=').next().unwrap_or("");
        assert!(
            WEB_ENVIRONMENT.contains(&name),
            "{name} is not a web setting"
        );
    }
}

/// `Containerfile.web` against the files it must agree with.
fn check_containerfile_web(
    text: &str,
    package_json: &str,
    unit: &str,
    dockerignore: &str,
) -> Result<(), String> {
    let arg = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("ARG {name}=")))
            .map(str::to_owned)
    };
    let node = arg("NODE").ok_or("no ARG NODE default")?;
    let pnpm = arg("PNPM").ok_or("no ARG PNPM default")?;
    let version = node
        .rsplit_once(':')
        .map(|(_, tag)| tag.split(['-', '@']).next().unwrap_or(""))
        .ok_or("NODE has no tag")?;
    let numbers: Vec<u32> = version.split('.').filter_map(|n| n.parse().ok()).collect();
    if numbers.len() != 3 {
        return Err(format!(
            "NODE tag `{version}` is not an exact x.y.z version"
        ));
    }
    if numbers[0] < 22 {
        return Err(format!("Node {version} is older than 22"));
    }
    if !package_json.contains(&format!("\"packageManager\": \"pnpm@{pnpm}\"")) {
        return Err(format!(
            "PNPM {pnpm} is not web/package.json's packageManager"
        ));
    }
    let stages: Vec<&str> = text.split("\nFROM ").skip(1).collect();
    if stages.len() != 2 {
        return Err(format!(
            "expected a build and a runtime stage, found {}",
            stages.len()
        ));
    }
    let (build, runtime) = (stages[0], stages[1]);
    if !build.contains("pnpm install --frozen-lockfile") {
        return Err("the build stage does not install with --frozen-lockfile".into());
    }
    if runtime
        .lines()
        .any(|line| line.starts_with("COPY") && line.contains(" . "))
    {
        return Err("the runtime stage copies the whole build context".into());
    }
    let copies: Vec<&str> = runtime
        .lines()
        .filter(|line| line.starts_with("COPY"))
        .collect();
    if copies.len() != 1 || !copies[0].contains("--from=build") || !copies[0].contains("/.output ")
    {
        return Err(format!(
            "the runtime stage must copy only the build's .output: {copies:?}"
        ));
    }
    let last = |prefix: &str| runtime.lines().rev().find(|line| line.starts_with(prefix));
    if last("USER ") != Some("USER sentinel-web") {
        return Err(format!(
            "runtime user is {:?}, not sentinel-web",
            last("USER ")
        ));
    }
    if !runtime.contains("--gid 10003") || !runtime.contains("--uid 10003") {
        return Err(
            "sentinel-web must be uid and gid 10003 (10001 is the controller, 10002 the worker)"
                .into(),
        );
    }
    if !runtime.contains("ENV NODE_ENV=production") {
        return Err("the runtime stage does not set NODE_ENV=production".into());
    }
    let port = runtime
        .split_whitespace()
        .find_map(|word| word.strip_prefix("PORT="))
        .ok_or("no PORT in the runtime stage")?;
    if last("EXPOSE ") != Some(format!("EXPOSE {port}").as_str()) {
        return Err(format!("EXPOSE is not the listening port {port}"));
    }
    if !runtime.contains("HEALTHCHECK") || !runtime.contains("CMD [\"/usr/local/bin/node\"") {
        return Err("no exec-form HEALTHCHECK through node".into());
    }
    let script = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart=/usr/bin/node "))
        .ok_or("the unit has no ExecStart through node")?;
    if last("ENTRYPOINT ")
        != Some(format!("ENTRYPOINT [\"/usr/local/bin/node\", \"{script}\"]").as_str())
    {
        return Err(format!("ENTRYPOINT does not run {script} like the unit"));
    }
    let ignored: Vec<&str> = dockerignore.lines().map(str::trim).collect();
    for entry in ["node_modules", ".env", ".env.*"] {
        if !ignored.contains(&entry) {
            return Err(format!("web/.dockerignore does not list {entry}"));
        }
    }
    Ok(())
}

fn containerfile_web_inputs() -> (String, String, String, String) {
    (
        read("Containerfile.web"),
        repo_file("web/package.json"),
        read("sentinel-web.service"),
        repo_file("web/.dockerignore"),
    )
}

#[test]
fn containerfile_web_is_pinned_unprivileged_and_reproducible() {
    let (file, package, unit, ignore) = containerfile_web_inputs();
    check_containerfile_web(&file, &package, &unit, &ignore)
        .unwrap_or_else(|error| panic!("examples/Containerfile.web: {error}"));
}

#[test]
fn the_server_package_ships_every_web_example() {
    let script = repo_file("scripts/release/package.sh");
    let expected = script
        .lines()
        .find(|line| line.trim_start().starts_with("server) echo"))
        .expect("the expected-entries line of the server package");
    let call = script
        .lines()
        .skip_while(|line| !line.starts_with("package server "))
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    for file in [
        "examples/Containerfile.web",
        "examples/sentinel-web.container",
        "examples/sentinel.network",
    ] {
        assert!(example(&file["examples/".len()..]).is_file(), "{file}");
        assert!(expected.contains(file), "package.sh does not expect {file}");
        assert!(call.contains(file), "package.sh does not package {file}");
    }
}

/// `text` with the first `from` inside the `web` service (and after it) replaced by `to`.
fn mutate_web(text: &str, from: &str, to: &str) -> String {
    let (head, web) = text.split_once("\n  web:\n").expect("a web service");
    assert!(web.contains(from), "the web service has no `{from}`");
    format!("{head}\n  web:\n{}", web.replacen(from, to, 1))
}

fn rejects(compose: &str, toml: &str, needle: &str) {
    match check_web_service(compose, toml) {
        Ok(()) => panic!("accepted a web service that must be refused for `{needle}`"),
        Err(error) => assert!(error.contains(needle), "`{error}` does not name `{needle}`"),
    }
}

#[test]
fn a_weakened_web_service_is_refused() {
    let compose = read("compose.server.yaml");
    let toml = read("server-container.toml");
    // The shipped files pass, so the refusals below are not vacuous.
    check_web_service(&compose, &toml).unwrap();

    let env = "      NODE_ENV: production\n";
    let add_env = |line: &str| mutate_web(&compose, env, &format!("      {line}\n{env}"));
    rejects(&add_env("GITHUB_TOKEN: abc"), &toml, "GITHUB_TOKEN");
    rejects(&add_env("SENTINEL_API_KEY: abc"), &toml, "SENTINEL_API_KEY");
    rejects(&add_env("EXTRA_SETTING: 1"), &toml, "EXTRA_SETTING");

    let port = "\"127.0.0.1:3000:3000\"";
    rejects(
        &mutate_web(&compose, port, "\"0.0.0.0:3000:3000\""),
        &toml,
        "127.0.0.1 only",
    );
    rejects(
        &mutate_web(&compose, port, "\"3000:3000\""),
        &toml,
        "127.0.0.1 only",
    );
    rejects(
        &compose.replacen("\"127.0.0.1:7080:7080\"", "\"7080:7080\"", 1),
        &toml,
        "service `server`",
    );

    let image = "image: localhost/sentinel-web:${SENTINEL_VERSION:-0.1.0-dev}";
    rejects(
        &mutate_web(&compose, image, "image: localhost/sentinel-web:${TAG}"),
        &toml,
        "TAG",
    );
    rejects(
        &mutate_web(&compose, image, "image: localhost/sentinel-web:latest"),
        &toml,
        "latest",
    );

    let depends = "    depends_on:\n      server:\n        condition: service_healthy\n";
    rejects(&mutate_web(&compose, depends, ""), &toml, "service_healthy");
    rejects(
        &mutate_web(&compose, "service_healthy", "service_started"),
        &toml,
        "service_healthy",
    );
    rejects(
        &mutate_web(&compose, "    read_only: true\n", ""),
        &toml,
        "read_only",
    );
    rejects(
        &mutate_web(&compose, "    cap_drop: [ALL]\n", ""),
        &toml,
        "capabilities",
    );
    rejects(
        &mutate_web(
            &compose,
            "    init: true\n",
            "    init: true\n    privileged: true\n",
        ),
        &toml,
        "privileged",
    );
    rejects(
        &mutate_web(&compose, "    mem_limit: 512m\n", ""),
        &toml,
        "mem_limit",
    );
    rejects(
        &mutate_web(&compose, "    profiles: [web]\n", ""),
        &toml,
        "profile",
    );

    let api = "SENTINEL_API: http://server:7080";
    rejects(
        &mutate_web(&compose, api, "SENTINEL_API: http://database:7080"),
        &toml,
        "database",
    );
    rejects(
        &mutate_web(&compose, api, "SENTINEL_API: http://server:7081"),
        &toml,
        "7081",
    );

    let proxies = "trusted_proxies = [\"10.89.77.10\"]";
    rejects(
        &compose,
        &toml.replace(proxies, "trusted_proxies = [\"10.89.77.11\"]"),
        "trusted_proxies",
    );
    rejects(
        &compose,
        &toml.replace(&format!("{proxies}\n"), ""),
        "trusted_proxies",
    );
    rejects(
        &mutate_web(
            &compose,
            "ipv4_address: 10.89.77.10",
            "ipv4_address: 10.90.0.10",
        ),
        &toml,
        "outside the subnet",
    );
}

#[test]
fn a_compose_file_with_a_credential_or_unknown_variable_is_refused() {
    let compose = read("compose.server.yaml");
    let after = "    restart: on-failure\n";
    let with = |extra: &str| compose.replacen(after, &format!("{after}{extra}\n"), 1);
    let error = check_compose_hygiene(&with("    env_file: .env")).unwrap_err();
    assert!(error.contains("env_file"), "{error}");
    let error = check_compose_hygiene(&with("    hostname: $HOME")).unwrap_err();
    assert!(error.contains("HOME"), "{error}");
    // `$$` is a literal dollar sign, not a reference.
    check_compose_hygiene(&with("    hostname: $$HOME")).unwrap();
}

#[test]
fn a_loosened_containerfile_web_is_refused() {
    let (file, package, unit, ignore) = containerfile_web_inputs();
    check_containerfile_web(&file, &package, &unit, &ignore).unwrap();
    let refused = |file: &str, ignore: &str, needle: &str| {
        let error = check_containerfile_web(file, &package, &unit, ignore)
            .expect_err("a loosened Containerfile.web must be refused");
        assert!(error.contains(needle), "`{error}` does not name `{needle}`");
    };
    let change = |from: &str, to: &str| {
        assert!(file.contains(from), "Containerfile.web has no `{from}`");
        file.replacen(from, to, 1)
    };
    refused(
        &change("node:22.22.1-slim", "node:latest"),
        &ignore,
        "exact",
    );
    refused(
        &change("node:22.22.1-slim", "node:20.11.0-slim"),
        &ignore,
        "older than 22",
    );
    refused(
        &change("RUN pnpm install --frozen-lockfile", "RUN pnpm install"),
        &ignore,
        "frozen-lockfile",
    );
    refused(
        &change("ARG PNPM=12.15.0", "ARG PNPM=11.0.0"),
        &ignore,
        "packageManager",
    );
    refused(
        &change("USER sentinel-web", "USER root"),
        &ignore,
        "runtime user",
    );
    refused(&change("--uid 10003", "--uid 10001"), &ignore, "10003");
    refused(
        &change(
            "COPY --from=build --chown=0:0 /src/.output /opt/sentinel/web/.output",
            "COPY . .",
        ),
        &ignore,
        "whole build context",
    );
    refused(
        &change("ENV NODE_ENV=production ", "ENV "),
        &ignore,
        "NODE_ENV",
    );
    refused(&change("EXPOSE 3000", "EXPOSE 8080"), &ignore, "EXPOSE");
    refused(
        &change(
            "/opt/sentinel/web/.output/server/index.mjs\"]",
            "/srv/app.mjs\"]",
        ),
        &ignore,
        "ENTRYPOINT",
    );
    refused(&file, "node_modules\n", ".env");
}
