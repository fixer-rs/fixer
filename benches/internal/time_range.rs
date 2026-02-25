use criterion::Criterion;
use fixer::internal::time_range::{utc, TimeOfDay, TimeRange};

pub fn benchmark_in_range(c: &mut Criterion) {
    let start = TimeOfDay::new(3, 0, 0);
    let end = TimeOfDay::new(18, 0, 0);
    let tr = TimeRange::new_utc(start, end);
    let now = jiff::civil::date(2016, 8, 10)
        .at(10, 0, 0, 0)
        .to_zoned(utc())
        .unwrap();

    c.bench_function("benchmark_in_range", |b| {
        b.iter(|| {
            tr.is_in_range(&now);
        });
    });
}
