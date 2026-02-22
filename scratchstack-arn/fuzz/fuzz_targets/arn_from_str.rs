#![no_main]
use {libfuzzer_sys::fuzz_target, scratchstack_arn::Arn, std::str::FromStr};

fuzz_target!(|data: String| {
    let _ = Arn::from_str(data.as_str());
});
