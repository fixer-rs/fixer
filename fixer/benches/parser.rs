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

pub fn benchmark_parser_read_message_json(c: &mut Criterion) {
    // JSON messages are typically framed by newlines or length-prefix.
    // This benchmark measures raw sonic-rs deserialization throughput on a
    // representative FIX JSON message, comparable to the TagValue parser
    // reading a message from a byte stream.
    const JSON_MSG: &str = r#"{"Header":{"BeginString":"FIXT.1.1","MsgType":"D","MsgSeqNum":4,"SenderCompID":"TW","SendingTime":"20140511-23:10:34","TargetCompID":"ISLD"},"Body":{"ClOrdID":"ID","HandlInst":"3","OrdType":"1","Side":"1","Symbol":"INTC","TransactTime":"20140511-23:10:34"},"Trailer":{}}"#;

    c.bench_function("parser_read_message_json", |b| {
        b.iter(|| {
            let _: sonic_rs::Value = sonic_rs::from_str(JSON_MSG).unwrap();
        });
    });
}

pub fn benchmark_parser_read_message_fixml(c: &mut Criterion) {
    const FIXML_MSG: &str = r#"<FIXML v="FIX.4.4"><Order ClOrdID="ID" HandlInst="3" Side="1" OrdTyp="1"><Instrmt Sym="INTC"/><Hdr SID="TW" TID="ISLD" SeqNum="4" Snt="20140511-23:10:34"/></Order></FIXML>"#;

    c.bench_function("parser_read_message_fixml", |b| {
        b.iter(|| {
            let _ = fastxml::Parser::from(FIXML_MSG.as_bytes()).parse().unwrap();
        });
    });
}
