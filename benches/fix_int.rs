use criterion::Criterion;
use fixer::{field::FieldValueReader, fix_int};

pub fn benchmark_fix_int_read(c: &mut Criterion) {
    let val = "1500";
    c.bench_function("fix_int_read", |b| {
        b.iter(|| {
            let mut field = fix_int::FIXInt::default();
            let _ = field.read(val);
        })
    });
}
