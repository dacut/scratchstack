#![feature(backtrace)]

use std::env;
use std::collections::HashMap;
// use std::error::Error;
use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader, Read};
use std::path::{PathBuf};
use std::str::from_utf8;

extern crate scratchstack_signature;
use scratchstack_signature::{AWSSigV4, Request};
use scratchstack_signature::signature::AWSSigV4Algorithm;

#[test]
fn test_aws4() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut aws4_testsuite_path = PathBuf::new();
    aws4_testsuite_path.push(manifest_dir);
    aws4_testsuite_path.push("tests");
    aws4_testsuite_path.push("aws4_testsuite");

    for entry_result in read_dir(aws4_testsuite_path).unwrap() {
        if let Ok(entry) = entry_result {
            let entry_path = entry.path();
            let ext = entry_path.extension().unwrap();
            if ext == "req" {
                run(&entry_path);
            }
        }
    }
}

fn run(req_path: &PathBuf) {
    let mut sreq_path = PathBuf::new();
    sreq_path.push(req_path);
    sreq_path.set_extension("sreq");

    let mut creq_path = PathBuf::new();
    creq_path.push(req_path);
    creq_path.set_extension("creq");

    let mut sts_path = PathBuf::new();
    sts_path.push(req_path);
    sts_path.set_extension("sts");

    let sreq = File::open(&sreq_path).expect(&format!("Failed to open {:?}", sreq_path));
    let mut sreq_r = BufReader::new(sreq);

    let mut method_line_full: String = String::new();
    sreq_r.read_line(&mut method_line_full).expect(&format!("No method line in {:?}", sreq_path));
    let method_line = method_line_full.trim_end();
    let muq_and_ver: Vec<&str> = method_line.rsplitn(2, " ").collect();
    assert_eq!(muq_and_ver.len(), 2, "muq_and_ver.len() != 2, method_line={}, {:?}", method_line, sreq_path);

    let muq_parts: Vec<&str> = muq_and_ver[1].splitn(2, " ").collect();
    assert_eq!(muq_parts.len(), 2, "muq_parts.len() != 2, method_line={}, muq_and_ver={:?}, muq_parts={:?}, {:?}", method_line, muq_and_ver, muq_parts, sreq_path);

    let method = muq_parts[0];
    let uri_and_query: Vec<&str> = muq_parts[1].splitn(2, "?").collect();
    let uri: String;
    let query: String;

    if uri_and_query.len() == 2 {
        uri = uri_and_query[0].to_string();
        query = uri_and_query[1].to_string();
    } else {
        uri = uri_and_query[0].to_string();
        query = "".to_string()
    }

    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut line_full: String = String::new();
    let mut last_key: Option<String> = None;

    while let Ok(n_read) = sreq_r.read_line(&mut line_full) {
        if n_read <= 0 {
            break;
        }

        let line = line_full.trim_end();
        if line.len() == 0 {
            break;
        }

        let key;
        let value;

        if line.starts_with(" ") || line.starts_with("\t") {
            key = last_key.unwrap();
            value = line.trim_start();
        } else {
            let parts: Vec<&str> = line.splitn(2, ":").collect();
            assert_eq!(parts.len(), 2, "Malformed header line: {} in {:?}", line, sreq_path);

            key = parts[0].to_lowercase();
            value = parts[1].trim();
        }

        last_key = Some((&key).to_string());

        if let Some(ref mut existing) = headers.get_mut(&key) {
            existing.push(value.as_bytes().to_vec());
        } else {
            let mut value_list: Vec<Vec<u8>> = Vec::new();
            value_list.push(value.as_bytes().to_vec());
            headers.insert(key, value_list);
        }

        line_full.clear();
    }

    let mut body: Vec<u8> = Vec::new();
    sreq_r.read_to_end(&mut body).unwrap();

    let request = Request {
        request_method: method.to_string(),
        uri_path: uri,
        query_string: query,
        headers: headers,
        body: &body,
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let mut creq = File::open(&creq_path).expect(&format!("Failed to open {:?}", creq_path));
    let mut expected_canonical_request = Vec::new();
    creq.read_to_end(&mut expected_canonical_request).unwrap();
    expected_canonical_request.retain(|c| *c != b'\r');

    let mut sts = File::open(&sts_path).expect(&format!("Failed to open {:?}", sts_path));
    let mut expected_string_to_sign = Vec::new();
    sts.read_to_end(&mut expected_string_to_sign).unwrap();
    expected_string_to_sign.retain(|c| *c != b'\r');

    let sig = AWSSigV4::new();

    let canonical_request = sig.get_canonical_request(&request).expect(&format!("Failed to get canonical request: {:?}", sreq_path));
    let string_to_sign = sig.get_string_to_sign(&request).expect(&format!("Failed to get string to sign: {:?}", sreq_path));

    assert_eq!(from_utf8(&canonical_request), from_utf8(&expected_canonical_request), "Failed on {:?}", sreq_path);
    assert_eq!(from_utf8(&string_to_sign), from_utf8(&expected_string_to_sign), "Failed on {:?}", sreq_path);
}