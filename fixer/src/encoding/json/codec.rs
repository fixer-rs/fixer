use crate::datadictionary::{DataDictionary, FieldDef, MessageDef};
use crate::encoding::Codec;
use crate::field_map::FieldMap;
use crate::message::{Message, ParseError};
use crate::repeating_group::{RepeatingGroup, group_element};
use crate::tag::{TAG_BODY_LENGTH, TAG_CHECK_SUM, Tag};
use sonic_rs::{Array, JsonContainerTrait, JsonValueTrait, Number, Object, Value};
use std::sync::Arc;

/// JSON codec for FIX messages, compliant with the FIX JSON Encoding
/// specification from <https://www.fixtrading.org/standards/json-encoding/>.
///
/// Uses human-readable field names as keys, native JSON types for numbers and
/// booleans, and JSON arrays for repeating groups. Requires a
/// [`DataDictionary`] to map between tag numbers and field names.
///
/// TagValue-specific fields (`BodyLength` and `CheckSum`) are omitted since
/// they have no meaning outside the `TagValue` wire format.
///
/// Uses `sonic-rs` (SIMD-accelerated) for JSON serialization/deserialization.
///
/// Example output:
/// ```json
/// {
///   "Header": {
///     "BeginString": "FIX.4.4",
///     "MsgType": "D",
///     "SenderCompID": "BUY",
///     "TargetCompID": "SELL",
///     "MsgSeqNum": 4
///   },
///   "Body": {
///     "ClOrdID": "ORDER-001",
///     "Symbol": "AAPL",
///     "Side": "1",
///     "OrderQty": 100,
///     "OrdType": "2",
///     "Price": 150.25
///   },
///   "Trailer": {}
/// }
/// ```
pub struct JsonCodec {
    dd: Arc<DataDictionary>,
}

impl JsonCodec {
    pub fn new(dd: Arc<DataDictionary>) -> Self {
        Self { dd }
    }
}

// Tags to skip in JSON output (TagValue wire-format artifacts).
const SKIP_TAGS: &[Tag] = &[TAG_BODY_LENGTH, TAG_CHECK_SUM];

impl Codec for JsonCodec {
    fn decode(
        &self,
        data: &bytes::Bytes,
        _transport_dd: &Option<Arc<DataDictionary>>,
        _app_dd: &Option<Arc<DataDictionary>>,
    ) -> Result<Message, ParseError> {
        let json: Value = sonic_rs::from_slice(data).map_err(|e| ParseError {
            orig_error: format!("JSON parse error: {e}"),
        })?;

        if !json.is_object() {
            return Err(ParseError {
                orig_error: "JSON root must be an object".to_string(),
            });
        }

        let mut msg = Message::new();

        if let Some(header) = json.get("Header") {
            decode_section(header, &mut msg.header.field_map, &self.dd, Some(&self.dd.header))?;
        }
        if let Some(body) = json.get("Body") {
            let msg_type = msg.header.get_string(crate::tag::TAG_MSG_TYPE).ok();
            let msg_def = msg_type.and_then(|mt| self.dd.messages.get(&mt));
            decode_section(body, &mut msg.body.field_map, &self.dd, msg_def)?;
        }
        if let Some(trailer) = json.get("Trailer") {
            decode_section(trailer, &mut msg.trailer.field_map, &self.dd, Some(&self.dd.trailer))?;
        }

        Ok(msg)
    }

    fn encode(&self, msg: &mut Message) -> Vec<u8> {
        let msg_type = msg.header.get_string(crate::tag::TAG_MSG_TYPE).ok();
        let msg_def = msg_type.and_then(|mt| self.dd.messages.get(&mt));

        let mut obj = Object::with_capacity(3);
        obj.insert(
            "Header",
            encode_section(&mut msg.header.field_map, &self.dd, Some(&self.dd.header)),
        );
        obj.insert(
            "Body",
            encode_section(&mut msg.body.field_map, &self.dd, msg_def),
        );
        obj.insert(
            "Trailer",
            encode_section(&mut msg.trailer.field_map, &self.dd, Some(&self.dd.trailer)),
        );
        sonic_rs::to_vec(&obj).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

/// Encode a `FieldMap` section into a JSON object using field names from the DD.
fn encode_section(
    fm: &mut FieldMap,
    dd: &DataDictionary,
    msg_def: Option<&MessageDef>,
) -> Value {
    let mut obj = Object::new();

    // Collect fields from the FieldMap.
    let fields = fm.ordered_fields();

    let mut i = 0;
    while i < fields.len() {
        let (tag, _) = &fields[i];
        let tag = *tag;

        if SKIP_TAGS.contains(&tag) {
            i += 1;
            continue;
        }

        // Check if this tag is a repeating group counter.
        if let Some(group_def) = msg_def
            .and_then(|md| md.fields.get(&tag))
            .filter(|fd| fd.is_group())
        {
            let (arr, consumed) = encode_group(&fields[i..], group_def, dd);
            let name = field_name(dd, tag);
            obj.insert(&name, arr);
            i += consumed;
            continue;
        }

        let name = field_name(dd, tag);
        let value = &fields[i].1;
        obj.insert(&name, encode_value(dd, tag, value));
        i += 1;
    }

    Value::from(obj)
}

/// Encode a repeating group starting at `fields[0]` (the counter tag).
/// Returns the JSON array and the number of fields consumed.
fn encode_group(
    fields: &[(Tag, &[u8])],
    group_def: &FieldDef,
    dd: &DataDictionary,
) -> (Value, usize) {
    // Every tag reachable from this group, so the run of members can be found.
    let child_tags: std::collections::HashSet<Tag> =
        group_def.child_tags().into_iter().collect();

    // The delimiter is the group's first member; each occurrence starts an entry.
    let delimiter_tag = group_def.fields.first().map(FieldDef::tag);

    let mut arr = Array::new();
    let mut consumed = 1; // counter field
    let mut current_entry = Object::new();
    let mut entry_has_fields = false;

    let mut i = 1;
    while i < fields.len() {
        let (tag, value) = fields[i];
        if !child_tags.contains(&tag) {
            break;
        }

        // Start a new group entry when we see the delimiter tag again.
        if Some(tag) == delimiter_tag && entry_has_fields {
            arr.push(Value::from(std::mem::replace(&mut current_entry, Object::new())));
        }

        // A nested group becomes a nested array. Encoding it as a plain field
        // would write its counter and then flatten its members into this
        // entry, where the unique-key rule drops all but the last.
        if let Some(nested_def) = group_def
            .fields
            .iter()
            .find(|fd| fd.tag() == tag)
            .filter(|fd| fd.is_group())
        {
            let (nested, nested_consumed) = encode_group(&fields[i..], nested_def, dd);
            current_entry.insert(&field_name(dd, tag), nested);
            entry_has_fields = true;
            i += nested_consumed;
            consumed += nested_consumed;
            continue;
        }

        current_entry.insert(&field_name(dd, tag), encode_value(dd, tag, value));
        entry_has_fields = true;
        i += 1;
        consumed += 1;
    }

    // Push the last entry.
    if entry_has_fields {
        arr.push(Value::from(current_entry));
    }

    (Value::from(arr), consumed)
}

/// Encode a field value using native JSON types based on the FIX field type.
fn encode_value(dd: &DataDictionary, tag: Tag, value: &[u8]) -> Value {
    let val_str = String::from_utf8_lossy(value);

    if let Some(ft) = dd.field_type_by_tag.get(&tag) {
        match ft.r#type.as_str() {
            "INT" | "LENGTH" | "SEQNUM" | "NUMINGROUP" | "TAGNUM" | "DAYOFMONTH" => {
                if let Ok(n) = val_str.parse::<i64>() {
                    return Value::from(n);
                }
            }
            "FLOAT" | "PRICE" | "QTY" | "AMT" | "PRICEOFFSET" | "PERCENTAGE" => {
                if let Ok(n) = val_str.parse::<f64>() {
                    // Use integer representation when there's no fractional part.
                    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                    if n.fract() == 0.0 && n.abs() < i64::MAX as f64 {
                        return Value::from(n as i64);
                    }
                    if let Some(n) = Number::from_f64(n) {
                        return Value::from(n);
                    }
                }
            }
            "BOOLEAN" => {
                return Value::from(&*val_str == "Y");
            }
            _ => {}
        }
    }

    Value::from(val_str.into_owned().as_str())
}

/// Look up the human-readable field name for a tag, falling back to the
/// tag number as a string if the DD doesn't know the tag.
fn field_name(dd: &DataDictionary, tag: Tag) -> String {
    dd.field_type_by_tag
        .get(&tag)
        .map_or_else(|| tag.to_string(), |ft| ft.name().to_string())
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

/// Decode a JSON object into a `FieldMap` section.
fn decode_section(
    json: &Value,
    field_map: &mut FieldMap,
    dd: &DataDictionary,
    msg_def: Option<&MessageDef>,
) -> Result<(), ParseError> {
    let obj = json.as_object().ok_or_else(|| ParseError {
        orig_error: "JSON section must be an object".to_string(),
    })?;

    for (key, value) in obj {
        let tag = resolve_tag(dd, key)?;

        // Check if this is a repeating group (JSON array).
        if let Some(arr) = value.as_array() {
            let group_def = msg_def.and_then(|md| md.fields.get(&tag));
            decode_group(tag, arr, field_map, dd, group_def)?;
            continue;
        }

        let val_str = json_value_to_fix_string(value)?;
        field_map.set_bytes(tag, val_str.as_bytes());
    }

    Ok(())
}

/// Decode a JSON array into a repeating group on the `FieldMap`.
fn decode_group(
    counter_tag: Tag,
    arr: &Array,
    field_map: &mut FieldMap,
    dd: &DataDictionary,
    group_def: Option<&FieldDef>,
) -> Result<(), ParseError> {
    // Build a GroupTemplate from the group definition so RepeatingGroup
    // can be constructed and written into the FieldMap.
    let template: Vec<Box<dyn crate::repeating_group::GroupItem>> = group_def
        .map(|gd| {
            gd.fields
                .iter()
                .map(|fd| group_element(fd.tag()))
                .collect()
        })
        .unwrap_or_default();

    let mut rg = RepeatingGroup::new(counter_tag, template);

    for entry in arr {
        let entry_obj = entry.as_object().ok_or_else(|| ParseError {
            orig_error: "Repeating group entry must be a JSON object".to_string(),
        })?;

        let group = rg.add();

        for (key, value) in entry_obj {
            let tag = resolve_tag(dd, key)?;

            // Nested repeating groups within a group entry.
            if let Some(nested_arr) = value.as_array() {
                let nested_def = group_def.and_then(|gd| {
                    gd.fields.iter().find(|f| f.tag() == tag)
                });
                decode_group(tag, nested_arr, &mut group.field_map, dd, nested_def)?;
                continue;
            }

            let val_str = json_value_to_fix_string(value)?;
            group.field_map.set_bytes(tag, val_str.as_bytes());
        }
    }

    field_map.set_group(rg);

    Ok(())
}

/// Resolve a JSON field name or tag number string to a FIX tag.
fn resolve_tag(dd: &DataDictionary, key: &str) -> Result<Tag, ParseError> {
    // Try as field name first.
    if let Some(ft) = dd.field_type_by_name.get(key) {
        return Ok(ft.tag());
    }
    // Fall back to numeric tag.
    key.parse().map_err(|_| ParseError {
        orig_error: format!("Unknown field name or invalid tag: {key}"),
    })
}

/// Convert a JSON value to a FIX string representation.
fn json_value_to_fix_string(value: &Value) -> Result<String, ParseError> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_string());
    }
    if let Some(n) = value.as_i64() {
        return Ok(n.to_string());
    }
    if let Some(n) = value.as_f64() {
        return Ok(n.to_string());
    }
    if let Some(b) = value.as_bool() {
        return Ok(if b { "Y" } else { "N" }.to_string());
    }
    Err(ParseError {
        orig_error: format!("Unsupported JSON value type: {value}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datadictionary::FieldType;
    use crate::fix_string::FIXString;
    use crate::repeating_group::{RepeatingGroup, group_element};
    use crate::tag::*;

    /// Build a minimal DataDictionary for testing.
    fn test_dd() -> Arc<DataDictionary> {
        let mut dd = DataDictionary::default();

        // Register field types with names and types.
        let fields = vec![
            (TAG_BEGIN_STRING, "BeginString", "STRING"),
            (TAG_BODY_LENGTH, "BodyLength", "LENGTH"),
            (TAG_MSG_TYPE, "MsgType", "STRING"),
            (TAG_SENDER_COMP_ID, "SenderCompID", "STRING"),
            (TAG_TARGET_COMP_ID, "TargetCompID", "STRING"),
            (TAG_MSG_SEQ_NUM, "MsgSeqNum", "SEQNUM"),
            (TAG_SENDING_TIME, "SendingTime", "UTCTIMESTAMP"),
            (TAG_CHECK_SUM, "CheckSum", "STRING"),
            (11, "ClOrdID", "STRING"),
            (21, "HandlInst", "CHAR"),
            (38, "OrderQty", "QTY"),
            (40, "OrdType", "CHAR"),
            (44, "Price", "PRICE"),
            (54, "Side", "CHAR"),
            (55, "Symbol", "STRING"),
            (60, "TransactTime", "UTCTIMESTAMP"),
            (110, "MinQty", "QTY"),
            (98, "EncryptMethod", "INT"),
            (108, "HeartBtInt", "INT"),
        ];

        for (tag, name, typ) in fields {
            let ft = FieldType::new(name.to_string(), tag, typ.to_string());
            dd.field_type_by_tag.insert(tag, ft.clone());
            dd.field_type_by_name.insert(name.to_string(), ft);
        }

        Arc::new(dd)
    }

    #[test]
    fn test_json_encode_field_names() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("BUY"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("SELL"));
        msg.header.set_int(TAG_MSG_SEQ_NUM, 4);
        msg.body.set_string(11, "ORDER-001");
        msg.body.set_string(55, "AAPL");
        msg.body.set_int(38, 100);

        let encoded = codec.encode(&mut msg);
        let json: Value = sonic_rs::from_slice(&encoded).unwrap();

        let header = json.get("Header").unwrap();
        assert_eq!(header.get("BeginString").unwrap().as_str().unwrap(), "FIX.4.4");
        assert_eq!(header.get("MsgType").unwrap().as_str().unwrap(), "D");
        assert_eq!(header.get("SenderCompID").unwrap().as_str().unwrap(), "BUY");
        assert_eq!(header.get("TargetCompID").unwrap().as_str().unwrap(), "SELL");
        assert_eq!(header.get("MsgSeqNum").unwrap().as_i64().unwrap(), 4);
        assert!(
            header.get("BodyLength").is_none(),
            "BodyLength should be omitted"
        );

        let body = json.get("Body").unwrap();
        assert_eq!(body.get("ClOrdID").unwrap().as_str().unwrap(), "ORDER-001");
        assert_eq!(body.get("Symbol").unwrap().as_str().unwrap(), "AAPL");
        assert_eq!(body.get("OrderQty").unwrap().as_i64().unwrap(), 100);

        let trailer = json.get("Trailer").unwrap();
        assert!(trailer.get("CheckSum").is_none());
    }

    #[test]
    fn test_json_encode_native_types() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("A"));
        msg.body.set_int(98, 0); // EncryptMethod: INT → JSON number
        msg.body.set_int(108, 30); // HeartBtInt: INT → JSON number

        let encoded = codec.encode(&mut msg);
        let json: Value = sonic_rs::from_slice(&encoded).unwrap();

        let body = json.get("Body").unwrap();
        assert_eq!(body.get("EncryptMethod").unwrap().as_i64().unwrap(), 0);
        assert_eq!(body.get("HeartBtInt").unwrap().as_i64().unwrap(), 30);
    }

    #[test]
    fn test_json_decode_field_names() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let json = r#"{
            "Header": {
                "BeginString": "FIX.4.4",
                "MsgType": "D",
                "SenderCompID": "BUY",
                "TargetCompID": "SELL",
                "MsgSeqNum": 4
            },
            "Body": {
                "ClOrdID": "ORDER-001",
                "Symbol": "AAPL",
                "Side": "1",
                "OrderQty": 100,
                "OrdType": "2",
                "Price": 150.25
            },
            "Trailer": {}
        }"#;
        let data = bytes::Bytes::from(json);

        let msg = codec.decode(&data, &None, &None).unwrap();

        assert_eq!(
            msg.header.get_string(TAG_BEGIN_STRING).unwrap(),
            "FIX.4.4"
        );
        assert!(msg.is_msg_type_of("D"));
        assert_eq!(msg.header.get_string(TAG_SENDER_COMP_ID).unwrap(), "BUY");
        assert_eq!(msg.header.get_int(TAG_MSG_SEQ_NUM).unwrap(), 4);
        assert_eq!(msg.body.get_string(11).unwrap(), "ORDER-001");
        assert_eq!(msg.body.get_string(55).unwrap(), "AAPL");
        assert_eq!(msg.body.get_int(38).unwrap(), 100);
        assert_eq!(msg.body.get_string(44).unwrap(), "150.25");
    }

    /// Real FIX 4.4 structure — the hand-built fixture has no nested groups.
    async fn fix44_dd() -> Arc<DataDictionary> {
        Arc::new(
            DataDictionary::parse("../spec/FIX44.xml")
                .await
                .expect("FIX44.xml"),
        )
    }

    /// Builds NewOrderList with one NoOrders entry carrying two NoPartyIDs.
    fn new_order_list_with_nested_group() -> Message {
        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("E"));
        msg.body.set_string(66, "LIST-1");

        let mut orders = RepeatingGroup::new(
            73,
            vec![
                group_element(11),
                group_element(67),
                Box::new(RepeatingGroup::new(
                    453,
                    vec![group_element(448), group_element(452)],
                )),
            ],
        );
        {
            let entry = orders.add();
            entry.field_map.set_string(11, "ORDER-1");
            entry.field_map.set_int(67, 1);

            let mut parties =
                RepeatingGroup::new(453, vec![group_element(448), group_element(452)]);
            for (id, role) in [("BROKER-A", 1), ("BROKER-B", 2)] {
                let p = parties.add();
                p.field_map.set_string(448, id);
                p.field_map.set_int(452, role);
            }
            entry.field_map.set_group(parties);
        }
        msg.body.set_group(orders);
        msg
    }

    /// A group nested in a group must become a nested array. It used to be
    /// flattened into the parent entry object, where the unique-key rule
    /// silently dropped every entry but the last.
    #[tokio::test]
    async fn test_json_encode_nested_group() {
        let codec = JsonCodec::new(fix44_dd().await);
        let mut msg = new_order_list_with_nested_group();

        let encoded = codec.encode(&mut msg);
        let json = String::from_utf8(encoded).unwrap();

        assert!(json.contains("BROKER-A"), "first entry was dropped: {json}");
        assert!(json.contains("BROKER-B"), "second entry was dropped: {json}");

        let value: Value = sonic_rs::from_str(&json).unwrap();
        let orders = value["Body"]["NoOrders"].as_array().unwrap();
        assert_eq!(1, orders.len());

        let parties = orders[0]["NoPartyIDs"]
            .as_array()
            .expect("NoPartyIDs must be a nested array, not flattened");
        assert_eq!(2, parties.len());
        assert_eq!("BROKER-A", parties[0]["PartyID"].as_str().unwrap());
        assert_eq!("BROKER-B", parties[1]["PartyID"].as_str().unwrap());
        assert_eq!(1, parties[0]["PartyRole"].as_i64().unwrap());
        assert_eq!(2, parties[1]["PartyRole"].as_i64().unwrap());
    }

    /// The array length carries the count, so the NumInGroup counter is not
    /// written — including for a nested group.
    #[tokio::test]
    async fn test_json_omits_group_counters() {
        let codec = JsonCodec::new(fix44_dd().await);
        let mut msg = new_order_list_with_nested_group();

        let json = String::from_utf8(codec.encode(&mut msg)).unwrap();
        let value: Value = sonic_rs::from_str(&json).unwrap();

        assert!(value["Body"]["NoOrders"].is_array());
        let entry = &value["Body"]["NoOrders"].as_array().unwrap()[0];
        assert!(
            entry["NoPartyIDs"].is_array(),
            "NoPartyIDs must be the group itself, not its count: {json}"
        );
    }

    #[tokio::test]
    async fn test_json_nested_group_round_trip() {
        let codec = JsonCodec::new(fix44_dd().await);
        let mut msg = new_order_list_with_nested_group();

        let encoded = codec.encode(&mut msg);
        let decoded = codec
            .decode(&bytes::Bytes::from(encoded), &None, &None)
            .unwrap();

        assert_eq!("LIST-1", decoded.body.get_string(66).unwrap());

        let orders = decoded
            .body
            .get_group(RepeatingGroup::new(
                73,
                vec![
                    group_element(11),
                    group_element(67),
                    Box::new(RepeatingGroup::new(
                        453,
                        vec![group_element(448), group_element(452)],
                    )),
                ],
            ))
            .expect("NoOrders should decode");
        assert_eq!(1, orders.len());

        let entry = orders.get(0);
        assert_eq!(b"ORDER-1", entry.field_map.get_bytes(11).unwrap());

        let parties = entry
            .field_map
            .get_group(RepeatingGroup::new(
                453,
                vec![group_element(448), group_element(452)],
            ))
            .expect("nested NoPartyIDs should survive the round trip");
        assert_eq!(2, parties.len());
        assert_eq!(b"BROKER-A", parties.get(0).field_map.get_bytes(448).unwrap());
        assert_eq!(b"BROKER-B", parties.get(1).field_map.get_bytes(448).unwrap());
    }

    /// FIX 4.4 nests three deep: NoOrders > NoPartyIDs > NoPartySubIDs.
    #[tokio::test]
    async fn test_json_three_level_nested_group() {
        let codec = JsonCodec::new(fix44_dd().await);

        let mut msg = Message::new();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("E"));
        msg.body.set_string(66, "LIST-1");

        let mut orders = RepeatingGroup::new(73, vec![group_element(11)]);
        {
            let entry = orders.add();
            entry.field_map.set_string(11, "ORDER-1");

            let mut parties = RepeatingGroup::new(453, vec![group_element(448)]);
            {
                let party = parties.add();
                party.field_map.set_string(448, "BROKER-A");

                let mut subs =
                    RepeatingGroup::new(802, vec![group_element(523), group_element(803)]);
                for (id, kind) in [("SUB-1", 1), ("SUB-2", 2)] {
                    let sub = subs.add();
                    sub.field_map.set_string(523, id);
                    sub.field_map.set_int(803, kind);
                }
                party.field_map.set_group(subs);
            }
            entry.field_map.set_group(parties);
        }
        msg.body.set_group(orders);

        let json = String::from_utf8(codec.encode(&mut msg)).unwrap();
        let value: Value = sonic_rs::from_str(&json).unwrap();

        let subs = value["Body"]["NoOrders"][0]["NoPartyIDs"][0]["NoPartySubIDs"]
            .as_array()
            .unwrap_or_else(|| panic!("three levels should nest: {json}"));
        assert_eq!(2, subs.len());
        assert_eq!("SUB-1", subs[0]["PartySubID"].as_str().unwrap());
        assert_eq!("SUB-2", subs[1]["PartySubID"].as_str().unwrap());
    }

    #[test]
    fn test_json_round_trip() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let mut msg = Message::new();
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.4"));
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("BUY"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("SELL"));
        msg.header.set_int(TAG_MSG_SEQ_NUM, 4);
        msg.body.set_string(11, "ORDER-001");
        msg.body.set_string(55, "AAPL");
        msg.body.set_string(54, "1");
        msg.body.set_int(38, 100);

        let encoded = codec.encode(&mut msg);
        let data = bytes::Bytes::from(encoded);
        let decoded = codec.decode(&data, &None, &None).unwrap();

        assert_eq!(
            decoded.header.get_string(TAG_BEGIN_STRING).unwrap(),
            "FIX.4.4"
        );
        assert!(decoded.is_msg_type_of("D"));
        assert_eq!(decoded.header.get_int(TAG_MSG_SEQ_NUM).unwrap(), 4);
        assert_eq!(decoded.body.get_string(11).unwrap(), "ORDER-001");
        assert_eq!(decoded.body.get_string(55).unwrap(), "AAPL");
        assert_eq!(decoded.body.get_int(38).unwrap(), 100);
    }

    #[test]
    fn test_json_decode_boolean() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let json = r#"{
            "Header": {"BeginString": "FIX.4.4", "MsgType": "D"},
            "Body": {"MinQty": 100},
            "Trailer": {}
        }"#;
        let data = bytes::Bytes::from(json);

        let msg = codec.decode(&data, &None, &None).unwrap();
        assert_eq!(msg.body.get_int(110).unwrap(), 100);
    }

    #[test]
    fn test_json_decode_invalid() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        // Not JSON
        let data = bytes::Bytes::from("not json");
        assert!(codec.decode(&data, &None, &None).is_err());

        // Not an object
        let data = bytes::Bytes::from("[1, 2, 3]");
        assert!(codec.decode(&data, &None, &None).is_err());

        // Unknown field name (not in DD, not a number)
        let json = r#"{"Header": {"UnknownField": "value"}, "Body": {}, "Trailer": {}}"#;
        let data = bytes::Bytes::from(json);
        assert!(codec.decode(&data, &None, &None).is_err());
    }

    #[test]
    fn test_json_from_parsed_tagvalue_message() {
        let dd = test_dd();
        let codec = JsonCodec::new(dd);

        let raw = b"8=FIX.4.4\x019=31\x0135=D\x0149=BUY\x0156=SELL\x0111=id\x0121=3\x0110=155\x01";
        let mut msg = Message::new();
        msg.parse_message(raw).unwrap();

        let encoded = codec.encode(&mut msg);
        let json: Value = sonic_rs::from_slice(&encoded).unwrap();

        let header = json.get("Header").unwrap();
        assert_eq!(header.get("BeginString").unwrap().as_str().unwrap(), "FIX.4.4");
        assert_eq!(header.get("MsgType").unwrap().as_str().unwrap(), "D");
        assert_eq!(header.get("SenderCompID").unwrap().as_str().unwrap(), "BUY");
        assert_eq!(header.get("TargetCompID").unwrap().as_str().unwrap(), "SELL");
        assert!(header.get("BodyLength").is_none());

        let body = json.get("Body").unwrap();
        assert_eq!(body.get("ClOrdID").unwrap().as_str().unwrap(), "id");
        assert_eq!(body.get("HandlInst").unwrap().as_str().unwrap(), "3");
    }
}
