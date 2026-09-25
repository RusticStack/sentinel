//! Offline key rotation goes through the operator's actual command surface.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::process::Command;

use sentinel_auth::sealed::Key;

#[test]
fn admin_rotation_keeps_earlier_ciphertext_readable_and_refuses_backup_reuse() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let backup = root.path().join("master.backup");
    let data_arg = data.to_str().unwrap();
    let backup_arg = backup.to_str().unwrap();
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(args)
            .output()
            .unwrap()
    };
    let created = invoke(&["admin", "key", "create", "--data-dir", data_arg]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let key_path = data.join("master.key");
    let before = Key::load(&key_path).unwrap().seal(b"owner", b"old");
    let args = [
        "admin",
        "key",
        "rotate",
        "--data-dir",
        data_arg,
        "--backup",
        backup_arg,
    ];
    let occupied = sentinel_store::Store::open(
        data.join(sentinel_store::METADATA_FILE),
        sentinel_store::Durability::Full,
    )
    .unwrap();
    let refused = invoke(&args);
    assert_eq!(refused.status.code(), Some(2));
    assert!(!backup.exists());
    drop(occupied);
    let rotated = invoke(&args);
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert_eq!(
        Key::load(&key_path)
            .unwrap()
            .open(b"owner", &before)
            .unwrap(),
        b"old"
    );
    assert_eq!(
        Key::load(&backup).unwrap().open(b"owner", &before).unwrap(),
        b"old"
    );
    let again = invoke(&args);
    assert_eq!(again.status.code(), Some(2));
    assert_eq!(
        Key::load(&key_path)
            .unwrap()
            .open(b"owner", &before)
            .unwrap(),
        b"old"
    );
}
