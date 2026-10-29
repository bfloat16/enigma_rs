use super::*;

#[test]
fn publishes_complete_output_and_preserves_existing_results() {
    let root = std::env::temp_dir().join(format!(
        "enigma-output-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let destination = root.join("results");
    let input = root.join("sample.exe");
    fs::write(&input, b"original").unwrap();
    assert!(
        publish_directory(&destination, |stage| {
            write_new_file(&stage.join("sample.exe"), b"restored")?;
            write_new_file(&stage.join("sample.exe"), b"conflict")
        })
        .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    publish_directory(&destination, |stage| {
        write_new_file(&stage.join("sample.exe"), b"restored")?;
        write_new_file(&stage.join("assets/data.bin"), b"content")
    })
    .unwrap();
    assert_eq!(
        fs::read(destination.join("sample.exe")).unwrap(),
        b"restored"
    );
    assert_eq!(
        fs::read(destination.join("assets/data.bin")).unwrap(),
        b"content"
    );
    assert!(
        publish_directory(&destination, |_| panic!(
            "existing output must not invoke writer"
        ))
        .is_err()
    );
    assert_eq!(
        fs::read(destination.join("sample.exe")).unwrap(),
        b"restored"
    );
    assert_eq!(fs::read(&input).unwrap(), b"original");
    fs::remove_dir_all(root).unwrap();
}
