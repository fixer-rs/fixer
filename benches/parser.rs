use criterion::Criterion;
use fixer::parser;
use tokio::io::BufReader;

pub fn benchmark_parser_read_message(c: &mut Criterion) {
    const STREAM: &str = "8=FIXT.1.19=11135=D34=449=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=2348=FIXT.1.19=9535=D34=549=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=198";

    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("parser_read_message", |b| {
        b.iter(|| {
            rt.block_on(async {
                let reader = BufReader::new(STREAM.as_bytes());
                let mut parser = parser::Parser::new(reader);
                let _ = parser.read_message().await;
            });
        });
    });
}
