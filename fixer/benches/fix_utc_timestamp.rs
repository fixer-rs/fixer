use criterion::Criterion;
use fixer::{field::FieldValueReader, fix_utc_timestamp::FIXUTCTimestamp};

pub fn benchmark_fix_utc_timestamp_read(c: &mut Criterion) {
    let seconds = "20160208-22:07:16";
    let millis = "20160208-22:07:16.954";
    let micros = "20160208-22:07:16.954123";
    let nanos = "20160208-22:07:16.954123123";

    c.bench_function("fix_utc_timestamp_read_seconds", |b| {
        b.iter(|| {
            let mut field = FIXUTCTimestamp::default();
            let _ = field.read(seconds.as_bytes());
        });
    });

    c.bench_function("fix_utc_timestamp_read_millis", |b| {
        b.iter(|| {
            let mut field = FIXUTCTimestamp::default();
            let _ = field.read(millis.as_bytes());
        });
    });

    c.bench_function("fix_utc_timestamp_read_micros", |b| {
        b.iter(|| {
            let mut field = FIXUTCTimestamp::default();
            let _ = field.read(micros.as_bytes());
        });
    });

    c.bench_function("fix_utc_timestamp_read_nanos", |b| {
        b.iter(|| {
            let mut field = FIXUTCTimestamp::default();
            let _ = field.read(nanos.as_bytes());
        });
    });
}
