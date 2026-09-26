//! Offline key rotation goes through the operator's actual command surface.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::process::Command;

use sentinel_auth::sealed::Key;

fn sentinel(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .unwrap()
}

/// A database holding one sealed value (a confirmed second-factor seed)
/// under the data directory's `master.key`.
fn sealed_database(data: &std::path::Path) {
    let created = sentinel(&[
        "admin",
        "key",
        "create",
        "--data-dir",
        data.to_str().unwrap(),
    ]);
    assert!(created.status.success());
    let key = Key::load(&data.join("master.key")).unwrap();
    let store = sentinel_store::Store::open(
        data.join(sentinel_store::METADATA_FILE),
        sentinel_store::Durability::Full,
    )
    .unwrap();
    let user = sentinel_core::UserId::new();
    let mut context = b"totp:".to_vec();
    context.extend_from_slice(user.as_bytes());
    let seed = key.seal(&context, b"0123456789abcdef0123");
    store
        .writer()
        .write(move |tx| {
            sentinel_store::auth::provisioning::insert_human(
                tx,
                user,
                "person",
                false,
                sentinel_core::UnixMillis(1),
            )?;
            tx.execute(
                "INSERT INTO mfa_totp(user_id,sealed_seed,created_ms,confirmed_ms) VALUES(?1,?2,1,2)",
                (user.as_bytes().as_slice(), seed.as_slice()),
            )?;
            Ok(())
        })
        .unwrap();
}

/// P10S-4: the controller reads only `<data_dir>/master.key`; with sealed
/// values stored and that key missing or not matching, it exits 2 before
/// listening instead of starting and failing each secret at first use.
#[test]
fn the_server_refuses_to_start_without_the_key_its_sealed_values_need() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    sealed_database(&data);
    let data_arg = data.to_str().unwrap();
    std::fs::remove_file(data.join("master.key")).unwrap();
    let missing = sentinel(&["server", "--data-dir", data_arg]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("master.key is missing"));

    // A different key (a mismatched restore) is refused the same way.
    assert!(
        sentinel(&["admin", "key", "create", "--data-dir", data_arg])
            .status
            .success()
    );
    let wrong = sentinel(&["server", "--data-dir", data_arg]);
    assert_eq!(wrong.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("does not open"));
}

/// P10S-5: rotate, reseal and retire through the operator's commands leave
/// a one-key file that still opens every stored value.
#[test]
fn admin_reseal_then_retire_leaves_one_key_that_opens_everything() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    sealed_database(&data);
    let data_arg = data.to_str().unwrap();
    let rotate_backup = root.path().join("pre-rotate.key");
    let retire_backup = root.path().join("pre-retire.key");
    let rotated = sentinel(&[
        "admin",
        "key",
        "rotate",
        "--data-dir",
        data_arg,
        "--backup",
        rotate_backup.to_str().unwrap(),
    ]);
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let resealed = sentinel(&[
        "admin",
        "key",
        "reseal",
        "--data-dir",
        data_arg,
        "--retire",
        "--backup",
        retire_backup.to_str().unwrap(),
    ]);
    assert!(
        resealed.status.success(),
        "{}",
        String::from_utf8_lossy(&resealed.stderr)
    );
    assert!(String::from_utf8_lossy(&resealed.stderr).contains("resealed 1 of 1"));
    let key = Key::load(&data.join("master.key")).unwrap();
    assert_eq!((key.len(), key.active_id()), (1, 2));
    let store = sentinel_store::Store::open(
        data.join(sentinel_store::METADATA_FILE),
        sentinel_store::Durability::Full,
    )
    .unwrap();
    store
        .read(|conn| sentinel_store::reseal::verify_key(conn, &key))
        .unwrap();
    let original = Key::load(&rotate_backup).unwrap();
    assert!(
        store
            .read(|conn| sentinel_store::reseal::verify_key(conn, &original))
            .is_err()
    );
}

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
