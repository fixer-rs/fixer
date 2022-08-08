use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub mod fix_float;

criterion_group!(benches, fix_float::benchmark_fix_float_read);
criterion_main!(benches);
