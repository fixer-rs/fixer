use criterion::{criterion_group, criterion_main};

pub mod fix_float;
pub mod fix_int;

criterion_group!(
    benches,
    fix_float::benchmark_fix_float_read,
    fix_int::benchmark_fix_int_read,
);
criterion_main!(benches);
