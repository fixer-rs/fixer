use criterion::{criterion_group, criterion_main};

pub mod fix_float;
pub mod fix_int;
pub mod internal;

criterion_group!(
    benches,
    fix_float::benchmark_fix_float_read,
    fix_int::benchmark_fix_int_read,
    internal::time_range::benchmark_in_range,
);
criterion_main!(benches);
