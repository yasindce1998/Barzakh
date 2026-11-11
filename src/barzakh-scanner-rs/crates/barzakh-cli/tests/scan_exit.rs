use std::process::Command;

#[test]
fn missing_input_json_has_failure_status_and_distinct_exit_code() {
    let missing = std::env::temp_dir().join(format!(
        "barzakh-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_barzakh-scanner"))
        .args(["scan", "--json", "--target"])
        .arg(missing)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "failed");
    assert!(!json["errors"].as_array().unwrap().is_empty());
}
