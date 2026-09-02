use {scratchstack_shapegen::*, std::time::Instant};
fn main() {
    let json = std::fs::read_to_string("scratchstack-shapes-iam/iam-2010-05-08.json").expect("read");
    let t = Instant::now();
    let mut model: SmithyModel = serde_json::from_str(&json).expect("parse");
    let parse = t.elapsed();
    model.add_default_shapes();
    let t = Instant::now();
    model.resolve();
    let resolve = t.elapsed();
    let t = Instant::now();
    let mut m = Modules::new();
    model.generate(&mut m);
    let tokens = t.elapsed();
    let t = Instant::now();
    let mut bytes = 0;
    for (n, ts) in [
        ("action", &m.action),
        ("error_meta", &m.error_meta),
        ("operation", &m.operation),
        ("types", &m.types),
        ("types_error", &m.types_error),
    ] {
        bytes += render(n, ts).len();
    }
    let render_time = t.elapsed();
    println!("parse JSON   {parse:>9.1?}");
    println!("resolve      {resolve:>9.1?}");
    println!("build tokens {tokens:>9.1?}");
    println!("render       {render_time:>9.1?}");
    println!("in-process   {:>9.1?}   ({bytes} bytes)", parse + resolve + tokens + render_time);
}
