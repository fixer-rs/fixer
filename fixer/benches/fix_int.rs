use criterion::Criterion;
use fixer::{field::FieldValueReader, fix_int};

pub fn benchmark_fix_int_read(c: &mut Criterion) {
    let small = "1500";
    let negative = "-99999";
    let large = "2147483647"; // i32::MAX
    let very_large = "9223372036854775807"; // i64::MAX

    // hybrid: scalar for <10 digits, atoi_simd for >=10 digits
    c.bench_function("fix_int_read_small", |b| {
        b.iter(|| {
            let mut field = fix_int::FIXInt::default();
            let _ = field.read(small.as_bytes());
        });
    });
    c.bench_function("fix_int_read_negative", |b| {
        b.iter(|| {
            let mut field = fix_int::FIXInt::default();
            let _ = field.read(negative.as_bytes());
        });
    });
    c.bench_function("fix_int_read_large", |b| {
        b.iter(|| {
            let mut field = fix_int::FIXInt::default();
            let _ = field.read(large.as_bytes());
        });
    });
    c.bench_function("fix_int_read_very_large", |b| {
        b.iter(|| {
            let mut field = fix_int::FIXInt::default();
            let _ = field.read(very_large.as_bytes());
        });
    });
}
