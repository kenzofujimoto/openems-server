//! Uninstall codes must match the Python reference (agent/uninstall.py) byte for byte.

use openems_agent::uninstall::{code, delivery_proof, derive_secret, normalize, release_token, verify};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../contract/uninstall-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn secret(case: &Value) -> Vec<u8> {
    hex::decode(case["secret"].as_str().unwrap()).unwrap()
}

#[test]
fn codes_and_release_tokens_match_python() {
    for case in vectors()["secrets"].as_array().unwrap() {
        let secret = secret(case);
        for item in case["codes"].as_array().unwrap() {
            let counter = item["counter"].as_u64().unwrap();
            assert_eq!(code(&secret, counter), item["code"].as_str().unwrap(), "{case}");
        }
        assert_eq!(release_token(&secret), case["release"].as_str().unwrap());
        assert_eq!(delivery_proof(&secret), case["delivery_proof"].as_str().unwrap());
    }
}

#[test]
fn secrets_derive_from_the_master_key_like_python() {
    let vectors = vectors();
    let master = vectors["master_key"].as_str().unwrap().as_bytes();
    for case in vectors["secrets"].as_array().unwrap() {
        assert_eq!(
            derive_secret(master, case["client_id"].as_str().unwrap()).unwrap().to_vec(),
            secret(case),
            "{case}"
        );
    }
    assert!(derive_secret(&master[..31], "client-1").is_err(), "short master key");
    assert!(derive_secret(master, "").is_err(), "empty client id");
}

#[test]
fn verification_matches_python() {
    let vectors = vectors();
    for case in vectors["verify"].as_array().unwrap() {
        let secret = secret(case);
        let expected = case["result"].as_u64();
        assert_eq!(
            verify(&secret, case["code"].as_str().unwrap(), case["last_used"].as_u64().unwrap()),
            expected,
            "{case}"
        );
    }
    for case in vectors["normalize"].as_array().unwrap() {
        assert_eq!(normalize(case["input"].as_str().unwrap()).as_deref(), case["result"].as_str(), "{case}");
    }
}
