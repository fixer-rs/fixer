use criterion::{criterion_group, criterion_main, Criterion};
use pprof::{
    criterion::{Output, PProfProfiler},
    flamegraph::Options,
};

pub(crate) mod fix_float;
pub(crate) mod fix_int;
pub(crate) mod internal;
pub(crate) mod message;
pub(crate) mod parser;

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(Some(Options::default()))));
    targets = fix_float::benchmark_fix_float_read, fix_int::benchmark_fix_int_read, internal::time_range::benchmark_in_range, parser::benchmark_parser_read_message,message::parse_message
}

criterion_main!(benches);
