use criterion::Criterion;
use fixer::datadictionary::{DataDictionary, FieldType};
use fixer::encoding::Codec;
use fixer::encoding::fixml::FixmlCodec;
use fixer::encoding::fixml::abbr::{ContentEntry, FixmlAbbreviations};
use fixer::encoding::json::JsonCodec;
use fixer::fix_string::FIXString;
use fixer::message::Message;
use fixer::tag::*;
use std::sync::Arc;

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

fn bench_dd() -> Arc<DataDictionary> {
    let mut dd = DataDictionary::default();
    let fields: &[(Tag, &str, &str)] = &[
        (TAG_BEGIN_STRING, "BeginString", "STRING"),
        (TAG_BODY_LENGTH, "BodyLength", "LENGTH"),
        (TAG_MSG_TYPE, "MsgType", "STRING"),
        (TAG_MSG_SEQ_NUM, "MsgSeqNum", "SEQNUM"),
        (TAG_SENDER_COMP_ID, "SenderCompID", "STRING"),
        (TAG_SENDING_TIME, "SendingTime", "UTCTIMESTAMP"),
        (TAG_TARGET_COMP_ID, "TargetCompID", "STRING"),
        (TAG_CHECK_SUM, "CheckSum", "STRING"),
        (11, "ClOrdID", "STRING"),
        (21, "HandlInst", "CHAR"),
        (38, "OrderQty", "QTY"),
        (40, "OrdType", "CHAR"),
        (54, "Side", "CHAR"),
        (55, "Symbol", "STRING"),
        (60, "TransactTime", "UTCTIMESTAMP"),
    ];
    for &(tag, name, typ) in fields {
        let ft = FieldType::new(name.to_string(), tag, typ.to_string());
        dd.field_type_by_tag.insert(tag, ft.clone());
        dd.field_type_by_name.insert(name.to_string(), ft);
    }
    Arc::new(dd)
}

pub fn parse_message_json(c: &mut Criterion) {
    let dd = bench_dd();
    let codec = JsonCodec::new(Arc::clone(&dd));

    // Build a representative JSON message (equivalent to the TagValue STREAM above).
    const JSON_MSG: &str = r#"{"Header":{"BeginString":"FIX.4.2","MsgType":"D","MsgSeqNum":2,"SenderCompID":"TW","SendingTime":"20140515-19:49:56.659","TargetCompID":"ISLD"},"Body":{"ClOrdID":"100","HandlInst":"1","OrdType":"1","Side":"1","Symbol":"TSLA","TransactTime":"00010101-00:00:00.000"},"Trailer":{}}"#;
    let json_bytes = bytes::Bytes::from(JSON_MSG);

    c.bench_function("parse_message_json", |b| {
        b.iter(|| {
            let _ = codec.decode(&json_bytes, &None, &None);
        });
    });

    c.bench_function("parse_and_read_json", |b| {
        b.iter(|| {
            let msg = codec.decode(&json_bytes, &None, &None).unwrap();
            let _ = msg.msg_type();
            let _ = msg.header.get_string(TAG_SENDER_COMP_ID);
            let _ = msg.body.get_string(55);
        });
    });

    // Encode benchmark: build a message, then encode to JSON.
    let mut msg = Message::new();
    msg.header.set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.2"));
    msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
    msg.header.set_int(TAG_MSG_SEQ_NUM, 2);
    msg.header.set_field(TAG_SENDER_COMP_ID, FIXString::from("TW"));
    msg.header.set_field(TAG_SENDING_TIME, FIXString::from("20140515-19:49:56.659"));
    msg.header.set_field(TAG_TARGET_COMP_ID, FIXString::from("ISLD"));
    msg.body.set_string(11, "100");
    msg.body.set_string(21, "1");
    msg.body.set_string(40, "1");
    msg.body.set_string(54, "1");
    msg.body.set_string(55, "TSLA");
    msg.body.set_string(60, "00010101-00:00:00.000");

    c.bench_function("encode_message_json", |b| {
        b.iter(|| {
            let mut msg_clone = msg.clone();
            let _ = codec.encode(&mut msg_clone);
        });
    });

    // For comparison: TagValue encode
    c.bench_function("encode_message_tagvalue", |b| {
        b.iter(|| {
            let mut msg_clone = msg.clone();
            let _ = msg_clone.build();
        });
    });
}

fn bench_fixml_abbr() -> Arc<FixmlAbbreviations> {
    let mut abbr = FixmlAbbreviations::new();
    abbr.fix_version = "FIX.4.4".to_string();
    abbr.add_field(TAG_BEGIN_STRING, "BgnStr");
    abbr.add_field(TAG_MSG_TYPE, "MsgTyp");
    abbr.add_field(TAG_SENDER_COMP_ID, "SID");
    abbr.add_field(TAG_TARGET_COMP_ID, "TID");
    abbr.add_field(TAG_MSG_SEQ_NUM, "SeqNum");
    abbr.add_field(TAG_SENDING_TIME, "Snt");
    abbr.add_field(11, "ClOrdID");
    abbr.add_field(21, "HandlInst");
    abbr.add_field(38, "OrdQty");
    abbr.add_field(40, "OrdTyp");
    abbr.add_field(54, "Side");
    abbr.add_field(55, "Sym");
    abbr.add_field(60, "TxnTm");
    abbr.add_message("D", "Order");
    abbr.add_component("Instrument", "Instrmt");
    abbr.add_component("OrderQtyData", "OrdQty");
    abbr.component_tags
        .insert("Instrument".to_string(), [55].into_iter().collect());
    abbr.component_tags
        .insert("OrderQtyData".to_string(), [38].into_iter().collect());
    abbr.msg_type_to_component_id
        .insert("D".to_string(), "14".to_string());
    abbr.component_name_to_id
        .insert("Instrument".to_string(), "1003".to_string());
    abbr.component_name_to_id
        .insert("OrderQtyData".to_string(), "1011".to_string());
    abbr.contents.insert(
        "14".to_string(),
        vec![
            ContentEntry { tag_text: "StandardHeader".into(), is_field: false, indent: 0, position: 1, required: true },
            ContentEntry { tag_text: "11".into(), is_field: true, indent: 0, position: 2, required: true },
            ContentEntry { tag_text: "21".into(), is_field: true, indent: 0, position: 3, required: false },
            ContentEntry { tag_text: "54".into(), is_field: true, indent: 0, position: 4, required: true },
            ContentEntry { tag_text: "40".into(), is_field: true, indent: 0, position: 5, required: true },
            ContentEntry { tag_text: "60".into(), is_field: true, indent: 0, position: 6, required: false },
            ContentEntry { tag_text: "Instrument".into(), is_field: false, indent: 0, position: 7, required: true },
            ContentEntry { tag_text: "OrderQtyData".into(), is_field: false, indent: 0, position: 8, required: true },
            ContentEntry { tag_text: "StandardTrailer".into(), is_field: false, indent: 0, position: 99, required: true },
        ],
    );
    Arc::new(abbr)
}

pub fn parse_message_fixml(c: &mut Criterion) {
    let dd = bench_dd();
    let abbr = bench_fixml_abbr();
    let codec = FixmlCodec::new(Arc::clone(&dd), Arc::clone(&abbr));

    const FIXML_MSG: &str = r#"<FIXML v="FIX.4.4"><Order ClOrdID="100" HandlInst="1" Side="1" OrdTyp="1" TxnTm="00010101-00:00:00.000"><Instrmt Sym="TSLA"/><OrdQty OrdQty="100"/><Hdr SID="TW" TID="ISLD" SeqNum="2" Snt="20140515-19:49:56.659"/></Order></FIXML>"#;
    let fixml_bytes = bytes::Bytes::from(FIXML_MSG);

    c.bench_function("parse_message_fixml", |b| {
        b.iter(|| {
            let _ = codec.decode(&fixml_bytes, &None, &None);
        });
    });

    c.bench_function("parse_and_read_fixml", |b| {
        b.iter(|| {
            let msg = codec.decode(&fixml_bytes, &None, &None).unwrap();
            let _ = msg.msg_type();
            let _ = msg.header.get_string(TAG_SENDER_COMP_ID);
            let _ = msg.body.get_string(55);
        });
    });

    let mut msg = Message::new();
    msg.header.set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
    msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
    msg.header.set_int(TAG_MSG_SEQ_NUM, 2);
    msg.header.set_field(TAG_SENDER_COMP_ID, FIXString::from("TW"));
    msg.header.set_field(TAG_SENDING_TIME, FIXString::from("20140515-19:49:56.659"));
    msg.header.set_field(TAG_TARGET_COMP_ID, FIXString::from("ISLD"));
    msg.body.set_string(11, "100");
    msg.body.set_string(21, "1");
    msg.body.set_string(40, "1");
    msg.body.set_string(54, "1");
    msg.body.set_string(55, "TSLA");
    msg.body.set_string(60, "00010101-00:00:00.000");
    msg.body.set_int(38, 100);

    c.bench_function("encode_message_fixml", |b| {
        b.iter(|| {
            let mut msg_clone = msg.clone();
            let _ = codec.encode(&mut msg_clone);
        });
    });
}
