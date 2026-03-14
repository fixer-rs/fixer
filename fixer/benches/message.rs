use criterion::Criterion;
use fixer::message::Message;

pub fn parse_message(c: &mut Criterion) {
    const STREAM: &str = "8=FIX.4.29=10435=D34=249=TW52=20140515-19:49:56.65956=ISLD11=10021=140=154=155=TSLA60=00010101-00:00:00.00010=039";
    c.bench_function("parse_message", |b| {
        b.iter(|| {
            let mut msg = Message::new();
            let _ = msg.parse_message(STREAM.as_bytes());
        });
    });
    c.bench_function("parse_message_reuse", |b| {
        let mut msg = Message::new();
        b.iter(|| {
            msg.reset();
            let _ = msg.parse_message(STREAM.as_bytes());
        });
    });
    c.bench_function("parse_and_read", |b| {
        let mut msg = Message::new();
        b.iter(|| {
            msg.reset();
            let _ = msg.parse_message(STREAM.as_bytes());
            let _ = msg.msg_type();
            let _ = msg.header.get_string(49);
            let _ = msg.body.get_string(55);
        });
    });
}
