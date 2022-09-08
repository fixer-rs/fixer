use chrono::{FixedOffset, NaiveDate};
use criterion::Criterion;
use fixer::internal::time_range::{TimeOfDay, TimeRange};
use std::ops::Add;

pub fn benchmark_in_range(c: &mut Criterion) {
    let start = TimeOfDay::new(3, 0, 0);
    let end = TimeOfDay::new(18, 0, 0);
    let tr = TimeRange::new_utc(start, end);
    let now = NaiveDate::from_ymd(2016, 8, 10)
        .and_hms(10, 0, 0)
        .add(FixedOffset::east(0));

    c.bench_function("benchmark_in_range", |b| {
        b.iter(|| {
            tr.is_in_range(&now);
        })
    });
}
