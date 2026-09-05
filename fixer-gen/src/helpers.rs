use fixer::datadictionary::{DataDictionary, FieldDef, MessageDef, MessagePart};

/// The fixer Rust type that a FIX XML type maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum FixerType {
    FIXString,
    FIXBoolean,
    FIXInt,
    FIXFloat,
    FIXDecimal,
    FIXUTCTimestamp,
}

impl FixerType {
    /// Returns the fixer type name as used in Rust code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FIXString => "FIXString",
            Self::FIXBoolean => "FIXBoolean",
            Self::FIXInt => "FIXInt",
            Self::FIXFloat => "FIXFloat",
            Self::FIXDecimal => "FIXDecimal",
            Self::FIXUTCTimestamp => "FIXUTCTimestamp",
        }
    }

}

#[cfg(test)]
impl FixerType {
    /// Returns the Rust value type for this fixer type.
    pub fn value_type(self) -> &'static str {
        match self {
            Self::FIXString => "String",
            Self::FIXBoolean => "bool",
            Self::FIXInt => "isize",
            Self::FIXFloat => "f64",
            Self::FIXDecimal => "Decimal",
            Self::FIXUTCTimestamp => "Timestamp",
        }
    }
}

/// Maps a FIX XML type string to the corresponding fixer Rust type.
///
/// Ports Go's `quickfixType()`. When `use_float` is true, numeric types
/// map to `FIXFloat` instead of `FIXDecimal`.
pub fn fixer_type(fix_xml_type: &str, use_float: bool) -> Result<FixerType, String> {
    match fix_xml_type {
        "MULTIPLESTRINGVALUE" | "MULTIPLEVALUESTRING" | "MULTIPLECHARVALUE" | "CHAR"
        | "CURRENCY" | "DATA" | "MONTHYEAR" | "LOCALMKTTIME" | "LOCALMKTDATE" | "TIME"
        | "DATE" | "EXCHANGE" | "LANGUAGE" | "XMLDATA" | "COUNTRY" | "UTCTIMEONLY" | "UTCDATE"
        | "UTCDATEONLY" | "TZTIMEONLY" | "TZTIMESTAMP" | "XID" | "XIDREF" | "STRING" => {
            Ok(FixerType::FIXString)
        }
        "BOOLEAN" => Ok(FixerType::FIXBoolean),
        "LENGTH" | "DAYOFMONTH" | "NUMINGROUP" | "SEQNUM" | "TAGNUM" | "INT" => {
            Ok(FixerType::FIXInt)
        }
        "UTCTIMESTAMP" => Ok(FixerType::FIXUTCTimestamp),
        "QTY" | "QUANTITY" | "AMT" | "PRICE" | "PRICEOFFSET" | "PERCENTAGE" | "FLOAT" => {
            if use_float {
                Ok(FixerType::FIXFloat)
            } else {
                Ok(FixerType::FIXDecimal)
            }
        }
        _ => Err(format!("Unknown FIX type: '{fix_xml_type}'")),
    }
}

/// Extracts the required fields from a message definition.
///
/// Ports Go's `requiredFields()`. Walks `required_parts`, pulling out
/// `FieldDef`s directly and the required fields of required `Component`s.
///
/// Repeating-group counter fields (`NumInGroup`) are included: they are
/// generated as plain integer fields, so a required group still contributes
/// its counter to the message constructor.
pub fn required_fields(msg_def: &MessageDef) -> Vec<&FieldDef> {
    let mut required = Vec::new();

    for part in &msg_def.required_parts {
        if !part.required() {
            continue;
        }
        match part {
            MessagePart::FieldDef(fd) => required.push(fd),
            MessagePart::Component(c) => required.extend(c.required_fields()),
            _ => {}
        }
    }

    required
}

/// Returns the FIX begin string for a spec (e.g., "FIX.4.4" or "FIXT.1.1").
///
/// Ports Go's `beginString()`.
pub fn begin_string(spec: &DataDictionary) -> String {
    if spec.fix_type == "FIXT" || spec.major == 5 {
        return "FIXT.1.1".to_string();
    }
    format!("FIX.{}.{}", spec.major, spec.minor)
}

/// Returns the begin string used for message routing.
///
/// Ports Go's `routerBeginString()`. For FIX 5.0+ specs, returns the
/// `ApplVerID` enum value instead of the begin string.
pub fn router_begin_string(spec: &DataDictionary) -> String {
    if spec.fix_type == "FIXT" {
        return "FIXT.1.1".to_string();
    }
    if spec.major != 5 && spec.service_pack == 0 {
        return format!("FIX.{}.{}", spec.major, spec.minor);
    }
    // ApplVerID enums
    match (spec.major, spec.minor, spec.service_pack) {
        (2, _, _) => "0".to_string(),
        (3, _, _) => "1".to_string(),
        (4, 0, _) => "2".to_string(),
        (4, 1, _) => "3".to_string(),
        (4, 2, _) => "4".to_string(),
        (4, 3, _) => "5".to_string(),
        (4, 4, _) => "6".to_string(),
        (5, 0, 0) => "7".to_string(),
        (5, 0, 1) => "8".to_string(),
        (5, 0, 2) => "9".to_string(),
        _ => String::new(),
    }
}

/// Returns the package/module name for a FIX spec (e.g., "fix44", "fix50sp2").
///
/// Ports Go's `getPackageName()`.
pub fn package_name(spec: &DataDictionary) -> String {
    let mut pkg = format!("{}{}{}", spec.fix_type.to_lowercase(), spec.major, spec.minor);
    if spec.service_pack != 0 {
        use std::fmt::Write;
        let _ = write!(pkg, "sp{}", spec.service_pack);
    }
    pkg
}

/// Returns the transport package name (header/trailer source).
///
/// FIX 5.0+ uses FIXT1.1 header/trailer; older versions use their own.
/// Ports Go's `getTransportPackageName()`.
pub fn transport_package_name(spec: &DataDictionary) -> String {
    if spec.major >= 5 {
        "fixt11".to_string()
    } else {
        package_name(spec)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use fixer::datadictionary::{DataDictionary, FieldDef};
    use tokio::runtime::Runtime;

    use crate::globals::{build_global_field_types, GlobalFieldType};

    fn parse_spec(path: &str) -> DataDictionary {
        Runtime::new()
            .unwrap()
            .block_on(DataDictionary::parse(path))
            .unwrap()
    }

    fn needs_decimal(
        msg_def: &MessageDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        msg_def
            .fields
            .values()
            .any(|fd| field_needs_decimal(fd, global_types, use_float))
    }

    fn field_needs_decimal(
        fd: &FieldDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        if let Some(gft) = global_types.get(fd.name()) {
            if let Ok(ft) = fixer_type(&gft.fix_type, use_float) {
                if ft == FixerType::FIXDecimal {
                    return true;
                }
            }
        }
        fd.fields
            .iter()
            .any(|child| field_needs_decimal(child, global_types, use_float))
    }

    fn needs_timestamp(
        msg_def: &MessageDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        msg_def
            .fields
            .values()
            .any(|fd| field_needs_timestamp(fd, global_types, use_float))
    }

    fn field_needs_timestamp(
        fd: &FieldDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        if let Some(gft) = global_types.get(fd.name()) {
            if let Ok(ft) = fixer_type(&gft.fix_type, use_float) {
                if ft == FixerType::FIXUTCTimestamp {
                    return true;
                }
            }
        }
        fd.fields
            .iter()
            .any(|child| field_needs_timestamp(child, global_types, use_float))
    }

    fn needs_enums(
        msg_def: &MessageDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        msg_def
            .fields
            .values()
            .any(|fd| field_needs_enum(fd, global_types, use_float))
    }

    fn field_needs_enum(
        fd: &FieldDef,
        global_types: &HashMap<String, GlobalFieldType>,
        use_float: bool,
    ) -> bool {
        if let Some(gft) = global_types.get(fd.name()) {
            if !gft.enums.is_empty() {
                if let Ok(ft) = fixer_type(&gft.fix_type, use_float) {
                    if ft != FixerType::FIXBoolean {
                        return true;
                    }
                }
            }
        }
        fd.fields
            .iter()
            .any(|child| field_needs_enum(child, global_types, use_float))
    }

    #[test]
    fn test_fixer_type_string_types() {
        for t in &[
            "STRING", "CHAR", "CURRENCY", "DATA", "MONTHYEAR", "EXCHANGE", "COUNTRY", "XMLDATA",
            "LOCALMKTDATE", "LOCALMKTTIME", "TIME", "DATE", "UTCTIMEONLY", "UTCDATE",
            "UTCDATEONLY", "TZTIMEONLY", "TZTIMESTAMP", "MULTIPLESTRINGVALUE",
            "MULTIPLEVALUESTRING", "MULTIPLECHARVALUE", "XID", "XIDREF", "LANGUAGE",
        ] {
            assert_eq!(fixer_type(t, false).unwrap(), FixerType::FIXString, "type: {t}");
        }
    }

    #[test]
    fn test_fixer_type_boolean() {
        assert_eq!(fixer_type("BOOLEAN", false).unwrap(), FixerType::FIXBoolean);
    }

    #[test]
    fn test_fixer_type_int_types() {
        for t in &["INT", "LENGTH", "DAYOFMONTH", "NUMINGROUP", "SEQNUM", "TAGNUM"] {
            assert_eq!(fixer_type(t, false).unwrap(), FixerType::FIXInt, "type: {t}");
        }
    }

    #[test]
    fn test_fixer_type_timestamp() {
        assert_eq!(
            fixer_type("UTCTIMESTAMP", false).unwrap(),
            FixerType::FIXUTCTimestamp
        );
    }

    #[test]
    fn test_fixer_type_numeric_decimal() {
        for t in &["FLOAT", "QTY", "QUANTITY", "AMT", "PRICE", "PRICEOFFSET", "PERCENTAGE"] {
            assert_eq!(fixer_type(t, false).unwrap(), FixerType::FIXDecimal, "type: {t}");
        }
    }

    #[test]
    fn test_fixer_type_numeric_use_float() {
        for t in &["FLOAT", "QTY", "QUANTITY", "AMT", "PRICE", "PRICEOFFSET", "PERCENTAGE"] {
            assert_eq!(fixer_type(t, true).unwrap(), FixerType::FIXFloat, "type: {t}");
        }
    }

    #[test]
    fn test_fixer_type_unknown() {
        assert!(fixer_type("BOGUS", false).is_err());
    }

    #[test]
    fn test_fixer_type_str_and_value_type() {
        assert_eq!(FixerType::FIXString.as_str(), "FIXString");
        assert_eq!(FixerType::FIXString.value_type(), "String");
        assert_eq!(FixerType::FIXBoolean.as_str(), "FIXBoolean");
        assert_eq!(FixerType::FIXBoolean.value_type(), "bool");
        assert_eq!(FixerType::FIXInt.as_str(), "FIXInt");
        assert_eq!(FixerType::FIXInt.value_type(), "isize");
        assert_eq!(FixerType::FIXFloat.as_str(), "FIXFloat");
        assert_eq!(FixerType::FIXFloat.value_type(), "f64");
        assert_eq!(FixerType::FIXDecimal.as_str(), "FIXDecimal");
        assert_eq!(FixerType::FIXDecimal.value_type(), "Decimal");
        assert_eq!(FixerType::FIXUTCTimestamp.as_str(), "FIXUTCTimestamp");
        assert_eq!(FixerType::FIXUTCTimestamp.value_type(), "Timestamp");
    }

    #[test]
    fn test_begin_string() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        assert_eq!(begin_string(&fix44), "FIX.4.4");

        let fixt11 = parse_spec("../spec/FIXT11.xml");
        assert_eq!(begin_string(&fixt11), "FIXT.1.1");

        let fix50 = parse_spec("../spec/FIX50.xml");
        assert_eq!(begin_string(&fix50), "FIXT.1.1");
    }

    #[test]
    fn test_router_begin_string() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        assert_eq!(router_begin_string(&fix44), "FIX.4.4");

        let fixt11 = parse_spec("../spec/FIXT11.xml");
        assert_eq!(router_begin_string(&fixt11), "FIXT.1.1");

        let fix50 = parse_spec("../spec/FIX50.xml");
        assert_eq!(router_begin_string(&fix50), "7");

        let fix50sp1 = parse_spec("../spec/FIX50SP1.xml");
        assert_eq!(router_begin_string(&fix50sp1), "8");

        let fix50sp2 = parse_spec("../spec/FIX50SP2.xml");
        assert_eq!(router_begin_string(&fix50sp2), "9");
    }

    #[test]
    fn test_package_name() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        assert_eq!(package_name(&fix44), "fix44");

        let fix50sp2 = parse_spec("../spec/FIX50SP2.xml");
        assert_eq!(package_name(&fix50sp2), "fix50sp2");

        let fixt11 = parse_spec("../spec/FIXT11.xml");
        assert_eq!(package_name(&fixt11), "fixt11");
    }

    #[test]
    fn test_transport_package_name() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        assert_eq!(transport_package_name(&fix44), "fix44");

        let fix50 = parse_spec("../spec/FIX50.xml");
        assert_eq!(transport_package_name(&fix50), "fixt11");

        let fix50sp2 = parse_spec("../spec/FIX50SP2.xml");
        assert_eq!(transport_package_name(&fix50sp2), "fixt11");
    }

    #[test]
    fn test_required_fields() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        // NewOrderSingle (MsgType=D) has required fields like ClOrdID, Side, TransactTime, OrdType
        let nos = fix44.messages.get("D").expect("NewOrderSingle not found");
        let req = required_fields(nos);
        assert!(!req.is_empty());

        let names: Vec<&str> = req.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"ClOrdID"), "ClOrdID should be required");
        assert!(names.contains(&"Side"), "Side should be required");
        assert!(names.contains(&"OrdType"), "OrdType should be required");

        // Required repeating-group counters are included: they are generated as
        // plain NumInGroup integer fields and so appear in the constructor.
        let nol = fix44.messages.get("E").expect("NewOrderList not found");
        let names: Vec<&str> = required_fields(nol).iter().map(|f| f.name()).collect();
        assert!(
            names.contains(&"NoOrders"),
            "required group counter NoOrders should be included, got {names:?}"
        );
    }

    #[test]
    fn test_needs_decimal() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));

        // NewOrderSingle has Price (decimal) field
        let nos = fix44.messages.get("D").unwrap();
        assert!(
            needs_decimal(nos, &globals.by_name, false),
            "NewOrderSingle should need decimal"
        );

        // With use_float=true, decimal is not needed
        assert!(
            !needs_decimal(nos, &globals.by_name, true),
            "NewOrderSingle should not need decimal with use_float"
        );
    }

    #[test]
    fn test_needs_timestamp() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));

        // NewOrderSingle has TransactTime (UTCTIMESTAMP) field
        let nos = fix44.messages.get("D").unwrap();
        assert!(
            needs_timestamp(nos, &globals.by_name, false),
            "NewOrderSingle should need timestamp"
        );
    }

    #[test]
    fn test_needs_enums() {
        let fix44 = parse_spec("../spec/FIX44.xml");
        let globals = build_global_field_types(std::slice::from_ref(&fix44));

        // NewOrderSingle has OrdType, Side etc. which have enums
        let nos = fix44.messages.get("D").unwrap();
        assert!(
            needs_enums(nos, &globals.by_name, false),
            "NewOrderSingle should need enums"
        );
    }
}
