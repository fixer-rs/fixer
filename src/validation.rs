use crate::datadictionary::{DataDictionary, FieldDef, TagSet};
use crate::errors::*;
use crate::field::*;
use crate::field_map::{FieldMap, LocalField};
use crate::fix_boolean::FIXBoolean;
use crate::fix_float::FIXFloat;
use crate::fix_int::FIXInt;
use crate::fix_string::FIXString;
use crate::fix_utc_timestamp::FIXUTCTimestamp;
use crate::message::Message;
use crate::msg_type::is_admin_message_type;
use crate::tag::*;
use crate::tag_value::TagValue;

// Validator validates a FIX message
pub trait Validator {
    fn validate(&self, message: &Message) -> MessageRejectErrorResult;
}

// ValidatorSettings describe validation behavior
pub struct ValidatorSettings {
    pub check_fields_out_of_order: bool,
    pub reject_invalid_message: bool,
}

// Default configuration for message validation.
// See http://www.quickfixengine.org/quickfix/doc/html/configuration.html.
impl Default for ValidatorSettings {
    fn default() -> Self {
        ValidatorSettings {
            check_fields_out_of_order: true,
            reject_invalid_message: true,
        }
    }
}

struct FixValidator {
    data_dictionary: DataDictionary,
    settings: ValidatorSettings,
}

impl Validator for FixValidator {
    // Validate tests the message against the provided data dictionary.
    fn validate(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.field_map.has(TAG_MSG_TYPE) {
            return Err(required_tag_missing(TAG_MSG_TYPE));
        }
        let msg_type = msg.header.field_map.get_string(TAG_MSG_TYPE)?;

        validate_fix(&self.data_dictionary, &self.settings, &msg_type, &msg)
    }
}

struct FixtValidator {
    transport_data_dictionary: DataDictionary,
    app_data_dictionary: DataDictionary,
    settings: ValidatorSettings,
}

impl Validator for FixtValidator {
    // validate tests the message against the provided transport and app data dictionaries.
    // If the message is an admin message, it will be validated against the transport data dictionary.
    fn validate(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.field_map.has(TAG_MSG_TYPE) {
            return Err(required_tag_missing(TAG_MSG_TYPE));
        }

        let msg_type = msg.header.field_map.get_string(TAG_MSG_TYPE)?;

        if is_admin_message_type(msg_type.chars().next().unwrap()) {
            return validate_fix(
                &self.transport_data_dictionary,
                &self.settings,
                &msg_type,
                &msg,
            );
        }

        validate_fixt(
            &self.transport_data_dictionary,
            &self.app_data_dictionary,
            &self.settings,
            &msg_type,
            &msg,
        )
    }
}

impl dyn Validator {
    // new creates a FIX message validator from the given data dictionaries
    pub fn new(
        settings: ValidatorSettings,
        app_data_dictionary: DataDictionary,
        transport_data_dictionary: Option<DataDictionary>,
    ) -> Box<Self> {
        if transport_data_dictionary.is_some() {
            return Box::new(FixtValidator {
                transport_data_dictionary: transport_data_dictionary.unwrap(),
                app_data_dictionary,
                settings,
            });
        }
        Box::new(FixValidator {
            data_dictionary: app_data_dictionary,
            settings,
        })
    }
}

fn validate_fix(
    d: &DataDictionary,
    settings: &ValidatorSettings,
    msg_type: &str,
    msg: &Message,
) -> MessageRejectErrorResult {
    validate_msg_type(d, msg_type, msg)?;

    validate_required(d, d, msg_type, msg)?;

    if settings.check_fields_out_of_order {
        validate_order(msg)?;
    }

    if settings.reject_invalid_message {
        validate_fields(d, d, msg_type, msg)?;

        validate_walk(d, d, msg_type, msg)?;
    }

    Ok(())
}

fn validate_fixt(
    transport_dd: &DataDictionary,
    app_dd: &DataDictionary,
    settings: &ValidatorSettings,
    msg_type: &str,
    msg: &Message,
) -> MessageRejectErrorResult {
    validate_msg_type(app_dd, msg_type, msg)?;

    validate_required(transport_dd, app_dd, msg_type, msg)?;

    if settings.check_fields_out_of_order {
        validate_order(msg)?;
    }

    validate_walk(transport_dd, app_dd, msg_type, msg)?;

    validate_fields(transport_dd, app_dd, msg_type, msg)?;

    Ok(())
}

fn validate_msg_type(
    d: &DataDictionary,
    msg_type: &str,
    _msg: &Message,
) -> MessageRejectErrorResult {
    if !d.messages.contains_key(msg_type) {
        return Err(invalid_message_type());
    }
    Ok(())
}

fn validate_walk(
    transport_dd: &DataDictionary,
    app_dd: &DataDictionary,
    msg_type: &str,
    msg: &Message,
) -> MessageRejectErrorResult {
    let mut remaining_fields = msg.fields.clone();
    let mut iterated_tags = TagSet::new();

    while remaining_fields.len() > 0 {
        let field = &remaining_fields[0];
        let tag = field.tag;

        let message_def = if tag.is_header() {
            &transport_dd.header
        } else if tag.is_trailer() {
            &transport_dd.trailer
        } else {
            &app_dd.messages[msg_type]
        };

        let field_def = message_def
            .fields
            .get(&tag)
            .ok_or(tag_not_defined_for_this_message_type(tag))?;

        if iterated_tags.0.contains(&tag) {
            return Err(tag_appears_more_than_once(tag));
        }

        iterated_tags.add(tag);

        let sent_remaining_fields = remaining_fields.to_owned();

        remaining_fields = validate_visit_field(field_def, &sent_remaining_fields)?;
    }

    if remaining_fields.len() != 0 {
        return Err(tag_not_defined_for_this_message_type(
            remaining_fields[0].tag,
        ));
    }

    Ok(())
}

fn validate_visit_field(
    field_def: &FieldDef,
    fields: &LocalField,
) -> Result<LocalField, Box<dyn MessageRejectErrorTrait>> {
    if field_def.is_group() {
        let new_fields = validate_visit_group_field(field_def, fields)?;
        return Ok(new_fields);
    }

    Ok(fields[1..].to_vec())
}

fn validate_visit_group_field(
    field_def: &FieldDef,
    field_stack: &LocalField,
) -> Result<LocalField, Box<dyn MessageRejectErrorTrait>> {
    let num_in_group_tag = field_stack[0].tag;
    let mut num_in_group = FIXInt::default();

    num_in_group
        .read(&field_stack[0].value)
        .map_err(|_| incorrect_data_format_for_value(num_in_group_tag))?;

    let mutable_field_stack = field_stack[1..].to_vec();

    let mut child_defs: Vec<FieldDef> = vec![];
    let mut group_count = 0;

    while mutable_field_stack.len() > 0 {
        // start of repeating group
        if mutable_field_stack[0].tag == field_def.fields[0].tag() {
            child_defs = field_def.fields.clone();
            group_count += 1;
        }

        // group complete
        if child_defs.is_empty() {
            break;
        }

        if mutable_field_stack[0].tag == child_defs[0].tag() {
            validate_visit_field(&child_defs[0], &mutable_field_stack)?;
        } else if child_defs[0].required() {
            return Err(required_tag_missing(child_defs[0].tag()));
        }

        child_defs = child_defs[1..].to_vec();
    }

    if group_count != num_in_group {
        return Err(incorrect_num_in_group_count_for_repeating_group(
            num_in_group_tag,
        ));
    }

    Ok(mutable_field_stack)
}

fn validate_order(msg: &Message) -> MessageRejectErrorResult {
    let mut in_header = true;
    let mut in_trailer = false;
    for field in msg.fields.iter() {
        let t = field.tag;
        if in_header && t.is_header() {}
        if in_header && !t.is_header() {
            in_header = false;
        }
        if !in_header && t.is_header() {
            return Err(tag_specified_out_of_required_order(t));
        }
        if t.is_trailer() {
            in_trailer = true;
        }
        if in_trailer && !t.is_trailer() {
            return Err(tag_specified_out_of_required_order(t));
        }
    }

    Ok(())
}

fn validate_required(
    transport_dd: &DataDictionary,
    app_dd: &DataDictionary,
    msg_type: &str,
    message: &Message,
) -> MessageRejectErrorResult {
    validate_required_field_map(
        message,
        &transport_dd.header.required_tags,
        &message.header.field_map,
    )?;

    let required_tags = &app_dd.messages.get(msg_type).unwrap().required_tags;
    validate_required_field_map(message, required_tags, &message.body.field_map)?;

    validate_required_field_map(
        message,
        &transport_dd.trailer.required_tags,
        &message.trailer.field_map,
    )?;

    Ok(())
}

pub fn validate_required_field_map(
    _msg: &Message,
    required_tags: &TagSet,
    field_map: &FieldMap,
) -> MessageRejectErrorResult {
    for required in required_tags.0.iter() {
        if !field_map.has(*required) {
            return Err(required_tag_missing(*required));
        }
    }

    Ok(())
}

fn validate_fields(
    transport_dd: &DataDictionary,
    app_dd: &DataDictionary,
    msg_type: &str,
    message: &Message,
) -> MessageRejectErrorResult {
    for field in message.fields.iter() {
        if field.tag.is_header() {
            validate_field(transport_dd, &transport_dd.header.tags, field)?;
        } else if field.tag.is_trailer() {
            validate_field(transport_dd, &transport_dd.trailer.tags, field)?;
        } else {
            let tags = &app_dd.messages.get(msg_type).unwrap().tags;
            validate_field(transport_dd, tags, field)?;
        }
    }

    Ok(())
}

fn validate_field(
    d: &DataDictionary,
    _valid_fields: &TagSet,
    field: &TagValue,
) -> MessageRejectErrorResult {
    if field.value.len() == 0 {
        return Err(tag_specified_without_a_value(field.tag));
    }

    if !d.field_type_by_tag.contains_key(&field.tag) {
        return Err(invalid_tag_number(field.tag));
    }

    let field_type = d.field_type_by_tag.get(&field.tag).unwrap();

    let allowed_values = &field_type.enums;
    if !allowed_values.is_empty()
        && !allowed_values.contains_key(String::from_utf8_lossy(&field.value).as_ref())
    {
        return Err(value_is_incorrect(field.tag));
    }

    let mut prototype = <dyn FieldValue>::default();

    match &(field_type.r#type) {
        str if str == "MULTIPLESTRINGVALUE" || str == "MULTIPLEVALUESTRING" => {}
        str if str == "MULTIPLECHARVALUE" => {}
        str if str == "CHAR" => {}
        str if str == "CURRENCY" => {}
        str if str == "DATA" => {}
        str if str == "MONTHYEAR" => {}
        str if str == "LOCALMKTDATE" || str == "DATE" => {}
        str if str == "EXCHANGE" => {}
        str if str == "LANGUAGE" => {}
        str if str == "XMLDATA" => {}
        str if str == "COUNTRY" => {}
        str if str == "UTCTIMEONLY" => {}
        str if str == "UTCDATEONLY" || str == "UTCDATE" => {}
        str if str == "TZTIMEONLY" => {}
        str if str == "TZTIMESTAMP" => {}
        str if str == "STRING" => prototype = Box::new(FIXString::new()),
        str if str == "BOOLEAN" => prototype = Box::new(FIXBoolean::default()),
        str if str == "LENGTH" => {}
        str if str == "DAYOFMONTH" => {}
        str if str == "NUMINGROUP" => {}
        str if str == "SEQNUM" => {}
        str if str == "INT" => prototype = Box::new(FIXInt::default()),
        str if str == "UTCTIMESTAMP" || str == "TIME" => {
            prototype = Box::new(FIXUTCTimestamp::default())
        }
        str if str == "QTY" || str == "QUANTITY" => {}
        str if str == "AMT" => {}
        str if str == "PRICE" => {}
        str if str == "PRICEOFFSET" => {}
        str if str == "PERCENTAGE" => {}
        str if str == "FLOAT" => prototype = Box::new(FIXFloat::default()),
        _ => {}
    }

    (*prototype)
        .read(&field.value)
        .map_err(|_| incorrect_data_format_for_value(field.tag))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datadictionary::parse;
    use crate::fix_utc_timestamp::TimestampPrecision;
    use chrono::Utc;

    struct ValidateTest {
        test_name: &'static str,
        validator: Box<dyn Validator>,
        message_bytes: Vec<u8>,
        expected_reject_reason: isize,
        expected_ref_tag_id: Option<Tag>,
        do_not_expect_reject: bool,
    }

    #[tokio::test]
    async fn test_validate() {
        let tests = vec![
            tc_invalid_tag_number_header().await,
            // tc_invalid_tag_number_body().await,
            // tc_invalid_tag_number_trailer().await,
            // tc_tag_specified_without_a_value().await,
            // tc_invalid_msg_type().await,
            // tc_value_is_incorrect().await,
            // tc_incorrect_data_format_for_value().await,
            // tc_tag_specified_out_of_required_order_header().await,
            // tc_tag_specified_out_of_required_order_trailer().await,
            // tc_tag_specified_out_of_required_order_disabled_header().await,
            // tc_tag_specified_out_of_required_order_disabled_trailer().await,
            // tc_tag_appears_more_than_once().await,
            // tc_float_validation().await,
            // tc_tag_not_defined_for_message().await,
            // tc_tag_is_defined_for_message().await,
            // tc_field_not_found_body().await,
            // tc_field_not_found_header().await,
            // tc_invalid_tag_check_disabled().await,
            // tc_invalid_tag_check_enabled().await,
        ];

        for test in tests.iter() {
            println!(
                "---------------------------------- {}",
                String::from_utf8_lossy(&test.message_bytes).as_ref()
            );
            let mut msg = Message::new();
            let parse_error = msg.parse_message(&test.message_bytes);
            // assert!(parse_error.is_ok());
            let reject_result = test.validator.validate(&msg);

            if reject_result.is_ok() {
                if test.do_not_expect_reject {
                    continue;
                }
                assert!(false, "{}: Expected reject", test.test_name);
            } else if reject_result.is_err() && test.do_not_expect_reject {
                assert!(
                    false,
                    "{}: Unexpected reject: {:?}",
                    test.test_name, reject_result
                );
            }

            // let reject = reject_result.unwrap_err();

            // assert_eq!(
            //     reject.reject_reason(),
            //     test.expected_reject_reason,
            //     "{}: Expected reason {} got {}",
            //     test.test_name,
            //     test.expected_reject_reason,
            //     reject.reject_reason(),
            // );

            // if reject.ref_tag_id().is_none() && test.expected_ref_tag_id.is_none() {
            //     // ok, expected and actual ref tag not set
            // } else if reject.ref_tag_id().is_some() && test.expected_ref_tag_id.is_none() {
            //     assert!(
            //         false,
            //         "{}: Unexpected RefTag '{}'",
            //         test.test_name,
            //         reject.ref_tag_id().unwrap()
            //     );
            // } else if reject.ref_tag_id().is_none() && test.expected_ref_tag_id.is_some() {
            //     assert!(
            //         false,
            //         "{}: Expected RefTag '{}'",
            //         test.test_name,
            //         test.expected_ref_tag_id.unwrap()
            //     );
            // } else if reject.ref_tag_id().unwrap() == test.expected_ref_tag_id.unwrap() {
            //     // ok, tags equal
            // } else {
            //     assert!(
            //         false,
            //         "{}: Expected RefTag '{}' got '{}'",
            //         test.test_name,
            //         test.expected_ref_tag_id.unwrap(),
            //         reject.ref_tag_id().unwrap()
            //     );
            // }
        }
    }

    fn create_fix40_new_order_single() -> Message {
        let mut msg = Message::new();
        let now = Utc::now().naive_utc();
        msg.header
            .field_map
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .field_map
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        msg.header
            .field_map
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        msg.header.field_map.set_field(
            TAG_SENDING_TIME,
            FIXUTCTimestamp {
                time: now,
                precision: TimestampPrecision::default(),
            },
        );

        msg.body.field_map.set_field(11, FIXString::from("A"));
        msg.body.field_map.set_field(21, FIXString::from("1"));
        msg.body.field_map.set_field(55, FIXString::from("A"));
        msg.body.field_map.set_field(54, FIXString::from("1"));
        msg.body.field_map.set_field(40, FIXString::from("1"));
        msg.body.field_map.set_field(38, 5 as FIXInt);
        msg.body.field_map.set_field(100, FIXString::from("0"));

        msg.trailer
            .field_map
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        msg
    }

    fn create_fix43_new_order_single() -> Message {
        let mut msg = Message::new();
        let now = Utc::now().naive_utc();
        msg.header
            .field_map
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .field_map
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.3"));
        msg.header
            .field_map
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        msg.header
            .field_map
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        msg.header.field_map.set_field(
            TAG_SENDING_TIME,
            FIXUTCTimestamp {
                time: now.clone(),
                precision: TimestampPrecision::default(),
            },
        );

        msg.body.field_map.set_field(11, FIXString::from("A"));
        msg.body.field_map.set_field(21, FIXString::from("1"));
        msg.body.field_map.set_field(55, FIXString::from("A"));
        msg.body.field_map.set_field(54, FIXString::from("1"));
        msg.body.field_map.set_field(38, 5 as FIXInt);
        msg.body.field_map.set_field(40, FIXString::from("1"));
        msg.body.field_map.set_field(
            60,
            FIXUTCTimestamp {
                time: now,
                precision: TimestampPrecision::default(),
            },
        );

        msg.trailer
            .field_map
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        msg
    }

    async fn tc_invalid_tag_number_header() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut invalid_header_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;

        invalid_header_field_message
            .header
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_header_field_message.build();

        ValidateTest {
            test_name: "Invalid Tag Number Header",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_body() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut invalid_body_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        invalid_body_field_message
            .body
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_body_field_message.build();

        ValidateTest {
            test_name: "Invalid Tag Number Body",
            validator,
            message_bytes: message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_trailer() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut invalid_trailer_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        invalid_trailer_field_message
            .trailer
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_trailer_field_message.build();

        ValidateTest {
            test_name: "Invalid Tag Number Trailer",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_not_defined_for_message() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut invalid_msg = create_fix40_new_order_single();
        let tag = 41 as Tag;
        invalid_msg
            .body
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_msg.build();

        ValidateTest {
            test_name: "Tag Not Defined For Message",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_NOT_DEFINED_FOR_THIS_MESSAGE_TYPE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_is_defined_for_message() -> ValidateTest {
        // compare to tcTagIsNotDefinedForMessage
        let dict = parse("./spec/FIX43.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut valid_msg = create_fix43_new_order_single();
        let message_bytes = valid_msg.build();

        ValidateTest {
            test_name: "TagIsDefinedForMessage",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER,
            expected_ref_tag_id: Some(666), // fake tag
        }
    }

    async fn tc_field_not_found_body() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut invalid_msg1 = Message::new();
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .field_map
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        invalid_msg1.header.field_map.set_field(
            TAG_SENDING_TIME,
            FIXUTCTimestamp {
                time: Utc::now().naive_utc(),
                precision: TimestampPrecision::default(),
            },
        );

        invalid_msg1
            .trailer
            .field_map
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        invalid_msg1
            .body
            .field_map
            .set_field(11, FIXString::from("A"));
        invalid_msg1
            .body
            .field_map
            .set_field(21, FIXString::from("A"));
        invalid_msg1
            .body
            .field_map
            .set_field(55, FIXString::from("A"));
        invalid_msg1
            .body
            .field_map
            .set_field(54, FIXString::from("A"));
        invalid_msg1
            .body
            .field_map
            .set_field(38, FIXString::from("A"));

        let tag = 40 as Tag;
        // ord type is required
        // invalid_msg1.body.field_map.set_field(Tag(40), "A"))

        let message_bytes = invalid_msg1.build();

        ValidateTest {
            test_name: "FieldNotFoundBody",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_field_not_found_header() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);

        let mut invalid_msg2 = Message::new();
        invalid_msg2
            .trailer
            .field_map
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        invalid_msg2
            .body
            .field_map
            .set_field(11, FIXString::from("A"));
        invalid_msg2
            .body
            .field_map
            .set_field(21, FIXString::from("A"));
        invalid_msg2
            .body
            .field_map
            .set_field(55, FIXString::from("A"));
        invalid_msg2
            .body
            .field_map
            .set_field(54, FIXString::from("A"));
        invalid_msg2
            .body
            .field_map
            .set_field(38, FIXString::from("A"));

        invalid_msg2
            .header
            .field_map
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg2
            .header
            .field_map
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        invalid_msg2
            .header
            .field_map
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg2
            .header
            .field_map
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .field_map
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .field_map
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        // sending time is required
        // invalid_msg2.Header.FieldMap.set_field(tag.SendingTime, "0"))

        let tag = TAG_SENDING_TIME;
        let message_bytes = invalid_msg2.build();

        ValidateTest {
            test_name: "FieldNotFoundHeader",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_without_a_value() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut builder = create_fix40_new_order_single();

        let bogus_tag = 109 as Tag;
        builder
            .body
            .field_map
            .set_field(bogus_tag, FIXString::from(""));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Tag SpecifiedWithoutAValue",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_WITHOUT_A_VALUE,
            expected_ref_tag_id: Some(bogus_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_msg_type() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut builder = create_fix40_new_order_single();
        builder
            .header
            .field_map
            .set_field(TAG_MSG_TYPE, FIXString::from("z"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Invalid MsgType",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_MSG_TYPE,
            expected_ref_tag_id: Some(666), // fake tag
            do_not_expect_reject: false,
        }
    }

    async fn tc_value_is_incorrect() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);

        let tag = 21 as Tag;
        let mut builder = create_fix40_new_order_single();
        builder.body.field_map.set_field(tag, FIXString::from("4"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "ValueIsIncorrect",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_VALUE_IS_INCORRECT,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_incorrect_data_format_for_value() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let mut builder = create_fix40_new_order_single();
        let tag = 38 as Tag;
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("+200.00"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "IncorrectDataFormatForValue",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_header() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // 	should be in header
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Tag specified out of required order in Header",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_trailer() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = TAG_SIGNATURE;
        // should be in trailer
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        let ref_tag = 100 as Tag;
        ValidateTest {
            test_name: "Tag specified out of required order in Trailer",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(ref_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_check_disabled() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = false;
        let validator = <dyn Validator>::new(custom_validator_settings, dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Invalid Tag Check - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_invalid_tag_check_enabled() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = true;
        let validator = <dyn Validator>::new(custom_validator_settings, dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Invalid Tag Check - Enabled",
            validator,
            message_bytes,
            do_not_expect_reject: false,
            expected_ref_tag_id: Some(tag),
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_header() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = <dyn Validator>::new(custom_validator_settings, dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // should be in header
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Tag specified out of required order in Header - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_trailer() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = <dyn Validator>::new(custom_validator_settings, dict, None);

        let mut builder = create_fix40_new_order_single();
        let tag = TAG_SIGNATURE;
        // should be in trailer
        builder
            .body
            .field_map
            .set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        ValidateTest {
            test_name: "Tag specified out of required order in Trailer - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_appears_more_than_once() -> ValidateTest {
        let dict = parse("./spec/FIX40.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let tag = 40 as Tag;

        ValidateTest {
        	test_name:  "Tag appears more than once",
        	validator,
        	message_bytes: "8=FIX.4.09=10735=D34=249=TW52=20060102-15:04:0556=ISLD11=ID21=140=140=254=138=20055=INTC60=20060102-15:04:0510=234".into(),
        	expected_reject_reason: REJECT_REASON_TAG_APPEARS_MORE_THAN_ONCE,
        	expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_float_validation() -> ValidateTest {
        let dict = parse("./spec/FIX42.xml").await.unwrap();
        let validator = <dyn Validator>::new(ValidatorSettings::default(), dict, None);
        let tag = 38 as Tag;
        ValidateTest{
            test_name:  "FloatValidation",
            validator,
            message_bytes: "8=FIX.4.29=10635=D34=249=TW52=20140329-22:38:4556=ISLD11=ID21=140=154=138=+200.0055=INTC60=20140329-22:38:4510=178".into(),
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    #[test]
    fn test_validate_visit_field() {
        // 	fieldType0 := datadictionary.NewFieldType("myfield", 11, "STRING")
        // 	fieldDef0 := &datadictionary.FieldDef{FieldType: fieldType0}

        // 	fieldType1 := datadictionary.NewFieldType("myfield", 2, "STRING")
        // 	fieldDef1 := &datadictionary.FieldDef{FieldType: fieldType1, Fields: []*datadictionary.FieldDef{}}

        // 	fieldType2 := datadictionary.NewFieldType("myfield", 3, "STRING")
        // 	fieldDef2 := &datadictionary.FieldDef{FieldType: fieldType2, Fields: []*datadictionary.FieldDef{}}

        // 	groupFieldType := datadictionary.NewFieldType("mygroupfield", 1, "INT")
        // 	groupFieldDef := &datadictionary.FieldDef{FieldType: groupFieldType, Fields: []*datadictionary.FieldDef{fieldDef1, fieldDef2}}

        // 	var field TagValue
        // 	field.init(Tag(11), []byte("value"))

        // 	var repField1 TagValue
        // 	var repField2 TagValue
        // 	repField1.init(Tag(2), []byte("a"))
        // 	repField2.init(Tag(3), []byte("a"))

        // 	var groupID TagValue
        // 	groupID.init(Tag(1), []byte("1"))

        // 	var groupID2 TagValue
        // 	groupID2.init(Tag(1), []byte("2"))

        // 	var groupID3 TagValue
        // 	groupID3.init(Tag(1), []byte("3"))

        // 	var tests = []struct {
        // 		fieldDef             *datadictionary.FieldDef
        // 		fields               []TagValue
        // 		expectedRemFields    int
        // 		expectReject         bool
        // 		expected_reject_reason int
        // 	}{
        // 		//non-repeating
        // 		{expectedRemFields: 0,
        // 			fieldDef: fieldDef0,
        // 			fields:   []TagValue{field}},
        // 		//single field group
        // 		{expectedRemFields: 0,
        // 			fieldDef: groupFieldDef,
        // 			fields:   []TagValue{groupID, repField1}},
        // 		//multiple field group
        // 		{expectedRemFields: 0,
        // 			fieldDef: groupFieldDef,
        // 			fields:   []TagValue{groupID, repField1, repField2}},
        // 		//test with trailing tag not in group
        // 		{expectedRemFields: 1,
        // 			fieldDef: groupFieldDef,
        // 			fields:   []TagValue{groupID, repField1, repField2, field}},
        // 		//repeats
        // 		{expectedRemFields: 1,
        // 			fieldDef: groupFieldDef,
        // 			fields:   []TagValue{groupID2, repField1, repField2, repField1, repField2, field}},
        // 		//REJECT: group size declared > actual group size
        // 		{expectReject: true,
        // 			fieldDef:             groupFieldDef,
        // 			fields:               []TagValue{groupID3, repField1, repField2, repField1, repField2, field},
        // 			expected_reject_reason: rejectReasonIncorrectNumInGroupCountForRepeatingGroup,
        // 		},
        // 		{expectReject: true,
        // 			fieldDef:             groupFieldDef,
        // 			fields:               []TagValue{groupID3, repField1, repField1, field},
        // 			expected_reject_reason: rejectReasonIncorrectNumInGroupCountForRepeatingGroup,
        // 		},
        // 		//REJECT: group size declared < actual group size
        // 		{expectReject: true,
        // 			fieldDef:             groupFieldDef,
        // 			fields:               []TagValue{groupID, repField1, repField2, repField1, repField2, field},
        // 			expected_reject_reason: rejectReasonIncorrectNumInGroupCountForRepeatingGroup,
        // 		},
        // 	}

        // 	for _, test := range tests {
        // 		remFields, reject := validateVisitField(test.fieldDef, test.fields)

        // 		if test.expectReject {
        // 			if reject == nil {
        // 				t.Error("Expected Reject")
        // 			}

        // 			if reject.RejectReason() != test.expected_reject_reason {
        // 				t.Errorf("Expected reject reason %v got %v", test.expected_reject_reason, reject.RejectReason())
        // 			}
        // 			continue
        // 		}

        // 		if reject != nil {
        // 			t.Errorf("Unexpected reject: %v", reject)
        // 		}

        // 		if len(remFields) != test.expectedRemFields {
        // 			t.Errorf("Expected len %v got %v", test.expectedRemFields, len(remFields))
        // 		}
        // 	}
    }
}
