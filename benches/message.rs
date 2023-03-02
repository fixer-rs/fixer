use criterion::Criterion;
use fixer::message::Message;

pub fn parse_message(c: &mut Criterion) {
    let val = "8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039";
    c.bench_function("parse_message", |b| {
        b.iter(|| {
            let mut msg = Message::new();
            let _ = msg.parse_message(val.as_bytes());
        });
    });
}
