use criterion::Criterion;
use fixer::parser;
use tokio::io::BufReader;

pub fn benchmark_parser_read_message(c: &mut Criterion) {
    const STREAM: &str = "8=FIXT.1.19=11135=D34=449=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=2348=FIXT.1.19=9535=D34=549=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=198";

    c.bench_function("parser_read_message", |b| {
        b.iter(|| {
            let reader = BufReader::new(STREAM.as_bytes());
            let mut parser = parser::Parser::new(reader);
            let _ = parser.read_message();
        });
    });
}
