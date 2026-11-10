//! Webhook HMAC signing — wire-format verification with a live test
//! receiver (Phase 0.3 of docs/ROADMAP.md).
//!
//! The receiver binds a real TCP socket, accepts the agent's webhook
//! delivery, and independently recomputes the HMAC-SHA256 signature from
//! the received timestamp and body — exactly what a production SIEM
//! webhook endpoint does.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use barzakh_agent::{constant_time_eq, deliver_webhook, webhook_signature};
use sha2::Digest;

/// Independent HMAC-SHA256 implementation for the receiver side.
fn receiver_hmac(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key = secret.to_vec();
    if key.len() > 64 {
        key = sha2::Sha256::digest(&key).to_vec();
    }
    key.resize(64, 0);
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = sha2::Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let mut outer = sha2::Sha256::new();
    outer.update(opad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Serve one HTTP request; return (headers, body).
fn receive_one(listener: &TcpListener) -> (Vec<(String, String)>, Vec<u8>) {
    let (stream, _) = listener.accept().unwrap();
    let mut stream = stream;
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in reader.by_ref().lines() {
        let line = line.unwrap();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    stream.write_all(response.as_bytes()).unwrap();
    (headers, body)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn signature_matches_reference_vector() {
    // Cross-checked against Python's hmac library:
    // hmac(b"test-secret", b"1700000000.{\"event\":\"tamper\"}", sha256)
    assert_eq!(
        webhook_signature("test-secret", "1700000000", br#"{"event":"tamper"}"#),
        "f3c299a8157a191de37939eb7b28bbd1f87c70eb470931c679025fb7f0f9d00f"
    );
    // Distinct inputs produce distinct signatures.
    assert_ne!(
        webhook_signature("test-secret", "1700000001", br#"{"event":"tamper"}"#),
        webhook_signature("test-secret", "1700000000", br#"{"event":"tamper"}"#)
    );
}

#[test]
fn receiver_verifies_signed_delivery() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/webhook");

    let event = serde_json::json!({"event": "firmware.tamper", "risk": 91});
    let secret = "s3cr3t-webhook-key";

    let deliver = std::thread::spawn(move || {
        deliver_webhook(&url, Some(secret), &event).unwrap();
    });

    let (headers, body) = receive_one(&listener);
    deliver.join().unwrap();

    // The delivery must carry the timestamp and signature headers.
    let timestamp = header(&headers, "x-barzakh-timestamp")
        .expect("timestamp header")
        .to_string();
    let signature = header(&headers, "x-barzakh-signature").expect("signature header");
    assert!(signature.starts_with("sha256="));

    // Receiver-side verification: recompute the HMAC over
    // "<timestamp>.<body>" and compare in constant time.
    let mut message = timestamp.clone().into_bytes();
    message.push(b'.');
    message.extend_from_slice(&body);
    let expected = receiver_hmac(secret.as_bytes(), &message);
    let received = signature.strip_prefix("sha256=").unwrap();
    let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        constant_time_eq(received.as_bytes(), expected_hex.as_bytes()),
        "signature mismatch: received {received}, expected {expected_hex}"
    );

    // The body is the JSON event.
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["event"], "firmware.tamper");
}

#[test]
fn unsigned_delivery_omits_signature_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/webhook");

    let event = serde_json::json!({"event": "firmware.tamper"});
    let deliver = std::thread::spawn(move || {
        deliver_webhook(&url, None, &event).unwrap();
    });

    let (headers, body) = receive_one(&listener);
    deliver.join().unwrap();

    assert!(header(&headers, "x-barzakh-signature").is_none());
    assert!(header(&headers, "x-barzakh-timestamp").is_none());
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["event"], "firmware.tamper");
}

#[test]
fn constant_time_eq_behaves() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
}
