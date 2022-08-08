use criterion::Criterion;
use fixer::{field::FieldValueReader, fix_float};

pub fn benchmark_fix_float_read(c: &mut Criterion) {
    let val = "15.1234";
    c.bench_function("fix_float_read", |b| {
        b.iter(|| {
            let mut field = fix_float::FIXFloat::default();
            let _ = field.read(val);
        })
    });
}
