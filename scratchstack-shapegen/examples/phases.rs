//! Times each stage of generation, for whichever model you point it at.
//!
//! This produces the phase breakdown quoted in the README. Run it from the workspace root:
//!
//! ```sh
//! cargo run --example phases -p scratchstack-shapegen -- scratchstack-shapes-iam/iam-2010-05-08.json
//! ```
//!
//! Build scripts are compiled with `[profile.dev.build-override]`, so `--release` is the closer
//! analogue of what a build actually pays; the default dev build shows what it would cost without
//! that setting.

use {
    scratchstack_shapegen::{Modules, SmithyModel, render},
    std::{path::PathBuf, time::Instant},
};

fn main() {
    let path = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: cargo run --example phases -p scratchstack-shapegen -- <model.json>");
        std::process::exit(2);
    });

    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    let start = Instant::now();
    let mut model: SmithyModel = serde_json::from_str(&json).expect("model should deserialize");
    let parse = start.elapsed();

    model.add_default_shapes();

    let start = Instant::now();
    model.resolve();
    let resolve = start.elapsed();

    let start = Instant::now();
    let mut modules = Modules::new();
    model.generate(&mut modules);
    let build_tokens = start.elapsed();

    let start = Instant::now();
    let bytes: usize = [
        ("action", &modules.action),
        ("error_meta", &modules.error_meta),
        ("operation", &modules.operation),
        ("types", &modules.types),
        ("types_error", &modules.types_error),
    ]
    .into_iter()
    .map(|(name, tokens)| render(name, tokens).len())
    .sum();
    let render_time = start.elapsed();

    println!("parse model   {parse:>9.1?}");
    println!("resolve       {resolve:>9.1?}");
    println!("build tokens  {build_tokens:>9.1?}");
    println!("render        {render_time:>9.1?}   (syn::parse2 + prettyplease)");
    println!("total         {:>9.1?}   {bytes} bytes generated", parse + resolve + build_tokens + render_time);
}
