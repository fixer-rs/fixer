use crate::datadictionary::{DataDictionary, FieldDef, TagSet};
use crate::errors::*;
use crate::field::*;
use crate::field_map::FieldMap;
use crate::fix_boolean::FIXBoolean;
use crate::fix_float::FIXFloat;
use crate::fix_int::FIXInt;
use crate::fix_string::FIXString;
use crate::fix_utc_timestamp::FIXUTCTimestamp;
use crate::message::Message;
use crate::msg_type::is_admin_message_type;
use crate::tag::*;
use crate::tag_value::TagValue;
use enum_dispatch::enum_dispatch;

// Validator validates a FIX message
#[enum_dispatch]
pub trait Validator {
    fn validate(&self, msg: &Message) -> MessageRejectErrorResult;
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

#[derive(Default)]
pub struct FixValidator {
    data_dictionary: DataDictionary,
    settings: ValidatorSettings,
}

impl Validator for FixValidator {
    // Validate tests the message against the provided data dictionary.
    fn validate(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_TYPE) {
            return Err(required_tag_missing(TAG_MSG_TYPE));
        }

        let msg_type = msg.header.get_string(TAG_MSG_TYPE)?;
        validate_fix(&self.data_dictionary, &self.settings, &msg_type, msg)
    }
}

#[derive(Default)]
pub struct FixtValidator {
    transport_data_dictionary: DataDictionary,
    app_data_dictionary: DataDictionary,
    settings: ValidatorSettings,
}

impl Validator for FixtValidator {
    // validate tests the message against the provided transport and app data dictionaries.
    // If the message is an admin message, it will be validated against the transport data dictionary.
    fn validate(&self, msg: &Message) -> MessageRejectErrorResult {
        if !msg.header.has(TAG_MSG_TYPE) {
            return Err(required_tag_missing(TAG_MSG_TYPE));
        }

        let msg_type = msg.header.get_string(TAG_MSG_TYPE)?;
        if is_admin_message_type(msg_type.as_bytes()) {
            return validate_fix(
                &self.transport_data_dictionary,
                &self.settings,
                &msg_type,
                msg,
            );
        }

        validate_fixt(
            &self.transport_data_dictionary,
            &self.app_data_dictionary,
            &self.settings,
            &msg_type,
            msg,
        )
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

    if settings.reject_invalid_message {
        validate_fields(transport_dd, app_dd, msg_type, msg)?;

        validate_walk(transport_dd, app_dd, msg_type, msg)?;
    }

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
    let mut iterated_tags = TagSet::new();
    let lock = msg.fields.data.lock();
    let mut fields = lock.get(..).unwrap();

    while !fields.is_empty() {
        let field = fields.get(0).unwrap();
        let tag = field.tag;

        let message_def = if tag.is_header() {
            &transport_dd.header
        } else if tag.is_trailer() {
            &transport_dd.trailer
        } else {
            app_dd.messages.get(msg_type).unwrap()
        };

        let field_def = message_def
            .fields
            .get(&tag)
            .ok_or_else(|| tag_not_defined_for_this_message_type(tag))?;

        if iterated_tags.0.contains(&tag) {
            return Err(tag_appears_more_than_once(tag));
        }

        iterated_tags.add(tag);

        fields = validate_visit_field(field_def, fields)?;
    }

    if !fields.is_empty() {
        return Err(tag_not_defined_for_this_message_type(
            fields.get(0).unwrap().tag,
        ));
    }

    Ok(())
}

fn validate_visit_field<'a>(
    field_def: &FieldDef,
    fields: &'a [TagValue],
) -> Result<&'a [TagValue], MessageRejectErrorEnum> {
    if field_def.is_group() {
        return validate_visit_group_field(field_def, fields);
    }

    Ok(fields.get(1..).unwrap())
}

fn validate_visit_group_field<'a>(
    field_def: &FieldDef,
    field_stack: &'a [TagValue],
) -> Result<&'a [TagValue], MessageRejectErrorEnum> {
    let first_field_stack = field_stack.get(0).unwrap();
    let num_in_group_tag = first_field_stack.tag;
    let mut num_in_group = FIXInt::default();

    num_in_group
        .read(&first_field_stack.value)
        .map_err(|_| incorrect_data_format_for_value(num_in_group_tag))?;

    let mut field_stack = field_stack.get(1..).unwrap();

    let mut child_defs: Vec<FieldDef> = vec![];
    let mut group_count = 0;

    while !field_stack.is_empty() {
        // start of repeating group
        if field_stack.get(0).unwrap().tag == field_def.fields[0].tag() {
            child_defs = field_def.fields.clone();
            group_count += 1;
        }

        // group complete
        if child_defs.is_empty() {
            break;
        }

        if field_stack.get(0).unwrap().tag == child_defs[0].tag() {
            field_stack = validate_visit_field(&child_defs[0], field_stack)?;
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

    Ok(field_stack)
}

fn validate_order(msg: &Message) -> MessageRejectErrorResult {
    let mut in_header = true;
    let mut in_trailer = false;
    for field in msg.fields.data.lock().get(..).unwrap().iter() {
        let t = field.tag;
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
    msg: &Message,
) -> MessageRejectErrorResult {
    validate_required_field_map(
        msg,
        &transport_dd.header.required_tags,
        &msg.header.field_map,
    )?;

    let required_tags = &app_dd.messages.get(msg_type).unwrap().required_tags;
    validate_required_field_map(msg, required_tags, &msg.body.field_map)?;

    validate_required_field_map(
        msg,
        &transport_dd.trailer.required_tags,
        &msg.trailer.field_map,
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
    msg: &Message,
) -> MessageRejectErrorResult {
    for field in msg.fields.data.lock().get(..).unwrap().iter() {
        if field.tag.is_header() {
            validate_field(transport_dd, &transport_dd.header.tags, field)?;
        } else if field.tag.is_trailer() {
            validate_field(transport_dd, &transport_dd.trailer.tags, field)?;
        } else {
            let tags = &app_dd.messages.get(msg_type).unwrap().tags;
            validate_field(app_dd, tags, field)?;
        }
    }

    Ok(())
}

fn validate_field(
    d: &DataDictionary,
    _valid_fields: &TagSet,
    field: &TagValue,
) -> MessageRejectErrorResult {
    if field.value.is_empty() {
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

    match field_type.r#type.as_str() {
        "MULTIPLESTRINGVALUE"
        | "MULTIPLEVALUESTRING"
        | "MULTIPLECHARVALUE"
        | "CHAR"
        | "CURRENCY"
        | "DATA"
        | "MONTHYEAR"
        | "LOCALMKTDATE"
        | "DATE"
        | "EXCHANGE"
        | "LANGUAGE"
        | "XMLDATA"
        | "COUNTRY"
        | "UTCTIMEONLY"
        | "UTCDATEONLY"
        | "UTCDATE"
        | "TZTIMEONLY"
        | "TZTIMESTAMP"
        | "STRING" => prototype = Box::<FIXString>::default(),
        "BOOLEAN" => prototype = Box::<FIXBoolean>::default(),
        "LENGTH" | "DAYOFMONTH" | "NUMINGROUP" | "SEQNUM" | "INT" => {
            prototype = Box::<FIXInt>::default()
        }
        "UTCTIMESTAMP" | "TIME" => prototype = Box::<FIXUTCTimestamp>::default(),
        "QTY" | "QUANTITY" | "AMT" | "PRICE" | "PRICEOFFSET" | "PERCENTAGE" | "FLOAT" => {
            prototype = Box::<FIXFloat>::default()
        }
        _ => {}
    }

    (*prototype)
        .read(&field.value)
        .map_err(|_| incorrect_data_format_for_value(field.tag))?;

    Ok(())
}

#[enum_dispatch(Validator)]
pub enum ValidatorEnum {
    Fix(FixValidator),
    Fixt(FixtValidator),
}

impl Default for ValidatorEnum {
    fn default() -> Self {
        Self::Fix(FixValidator::default())
    }
}

impl ValidatorEnum {
    // new creates a FIX message validator from the given data dictionaries
    pub fn new(
        settings: ValidatorSettings,
        app_data_dictionary: DataDictionary,
        transport_data_dictionary: Option<DataDictionary>,
    ) -> Self {
        if let Some(transport_data_dictionary) = transport_data_dictionary {
            return Self::Fixt(FixtValidator {
                transport_data_dictionary,
                app_data_dictionary,
                settings,
            });
        }
        Self::Fix(FixValidator {
            data_dictionary: app_data_dictionary,
            settings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datadictionary::{DataDictionary, FieldType},
        field_map::LocalField,
        fix_utc_timestamp::TimestampPrecision,
    };
    use chrono::Utc;
    use parking_lot::Mutex;
    use std::sync::Arc;

    struct ValidateTest<'a> {
        name: &'a str,
        validator: ValidatorEnum,
        message_bytes: Vec<u8>,
        expected_reject_reason: isize,
        expected_ref_tag_id: Option<Tag>,
        do_not_expect_reject: bool,
    }

    #[tokio::test]
    async fn test_validate() {
        let tests = vec![
            tc_invalid_tag_number_header().await,
            tc_invalid_tag_number_header_fix_t().await,
            tc_invalid_tag_number_body().await,
            tc_invalid_tag_number_body_fix_t().await,
            tc_invalid_tag_number_trailer().await,
            tc_invalid_tag_number_trailer_fix_t().await,
            tc_tag_specified_without_a_value().await,
            tc_tag_specified_without_a_value_fix_t().await,
            tc_invalid_msg_type().await,
            tc_invalid_msg_type_fix_t().await,
            tc_value_is_incorrect().await,
            tc_value_is_incorrect_fix_t().await,
            tc_incorrect_data_format_for_value().await,
            tc_incorrect_data_format_for_value_fix_t().await,
            tc_tag_specified_out_of_required_order_header().await,
            tc_tag_specified_out_of_required_order_header_fix_t().await,
            tc_tag_specified_out_of_required_order_trailer().await,
            tc_tag_specified_out_of_required_order_trailer_fix_t().await,
            tc_tag_specified_out_of_required_order_disabled_header().await,
            tc_tag_specified_out_of_required_order_disabled_header_fix_t().await,
            tc_tag_specified_out_of_required_order_disabled_trailer().await,
            tc_tag_specified_out_of_required_order_disabled_trailer_fix_t().await,
            tc_tag_appears_more_than_once().await,
            tc_tag_appears_more_than_once_fix_t().await,
            tc_float_validation().await,
            tc_float_validation_fix_t().await,
            tc_tag_not_defined_for_message().await,
            tc_tag_not_defined_for_message_fix_t().await,
            tc_tag_is_defined_for_message().await,
            tc_tag_is_defined_for_message_fix_t().await,
            tc_field_not_found_body().await,
            tc_field_not_found_body_fix_t().await,
            tc_field_not_found_header().await,
            tc_field_not_found_header_fix_t().await,
            tc_invalid_tag_check_disabled().await,
            tc_invalid_tag_check_disabled_fix_t().await,
            tc_invalid_tag_check_enabled().await,
            tc_invalid_tag_check_enabled_fix_t().await,
        ];

        for test in tests.iter() {
            let mut msg = Message::new();
            let parse_error = msg.parse_message(&test.message_bytes);
            assert!(parse_error.is_ok());

            let reject_result = test.validator.validate(&msg);
            if reject_result.is_ok() {
                if test.do_not_expect_reject {
                    continue;
                }
                assert!(false, "{}: Expected reject", test.name);
            } else if reject_result.is_err() && test.do_not_expect_reject {
                assert!(
                    false,
                    "{}: Unexpected reject: {:?}",
                    test.name, reject_result
                );
            }

            let reject = reject_result.unwrap_err();
            assert_eq!(
                reject.reject_reason(),
                test.expected_reject_reason,
                "{}: Expected reason {} got {}",
                test.name,
                test.expected_reject_reason,
                reject.reject_reason(),
            );

            if reject.ref_tag_id().is_none() && test.expected_ref_tag_id.is_none() {
                // ok, expected and actual ref tag not set
            } else if reject.ref_tag_id().is_some() && test.expected_ref_tag_id.is_none() {
                assert!(
                    false,
                    "{}: Unexpected RefTag '{}'",
                    test.name,
                    reject.ref_tag_id().unwrap()
                );
            } else if reject.ref_tag_id().is_none() && test.expected_ref_tag_id.is_some() {
                assert!(
                    false,
                    "{}: Expected RefTag '{}'",
                    test.name,
                    test.expected_ref_tag_id.unwrap()
                );
            } else if reject.ref_tag_id().unwrap() == test.expected_ref_tag_id.unwrap() {
                // ok, tags equal
            } else {
                assert!(
                    false,
                    "{}: Expected RefTag '{}' got '{}'",
                    test.name,
                    test.expected_ref_tag_id.unwrap(),
                    reject.ref_tag_id().unwrap()
                );
            }
        }
    }

    fn create_fix40_new_order_single() -> Message {
        let msg = Message::new();
        let now = Utc::now();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        msg.header.set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        msg.header.set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(now));

        msg.body.set_field(11, FIXString::from("A"));
        msg.body.set_field(21, FIXString::from("1"));
        msg.body.set_field(55, FIXString::from("A"));
        msg.body.set_field(54, FIXString::from("1"));
        msg.body.set_field(40, FIXString::from("1"));
        msg.body.set_field(38, 5 as FIXInt);
        msg.body.set_field(100, FIXString::from("0"));

        msg.trailer.set_field(TAG_CHECK_SUM, FIXString::from("000"));

        msg
    }

    fn create_fix43_new_order_single() -> Message {
        let msg = Message::new();
        let now = Utc::now();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.3"));
        msg.header.set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        msg.header.set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(now));

        msg.body.set_field(11, FIXString::from("A"));
        msg.body.set_field(21, FIXString::from("1"));
        msg.body.set_field(55, FIXString::from("A"));
        msg.body.set_field(54, FIXString::from("1"));
        msg.body.set_field(38, 5 as FIXInt);
        msg.body.set_field(40, FIXString::from("1"));
        msg.body.set_field(60, FIXUTCTimestamp::from_time(now));

        msg.trailer.set_field(TAG_CHECK_SUM, FIXString::from("000"));

        msg
    }

    fn create_fix50sp2_new_order_single() -> Message {
        let msg = Message::new();
        let now = Utc::now();
        msg.header.set_field(TAG_MSG_TYPE, FIXString::from("D"));
        msg.header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIXT.1.1"));
        msg.header.set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        msg.header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        msg.header.set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        msg.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(now));

        msg.body.set_field(11, FIXString::from("A"));
        msg.body.set_field(21, FIXString::from("1"));
        msg.body.set_field(55, FIXString::from("A"));
        msg.body.set_field(54, FIXString::from("1"));
        msg.body.set_field(40, FIXString::from("1"));
        msg.body.set_field(38, 5 as FIXInt);
        msg.body.set_field(
            60,
            FIXUTCTimestamp::from_time_with_precision(now, TimestampPrecision::Nanos),
        );
        msg.body.set_field(100, FIXString::from("0"));

        msg.trailer.set_field(TAG_CHECK_SUM, FIXString::from("000"));

        msg
    }

    async fn tc_invalid_tag_number_header<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let invalid_header_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;

        invalid_header_field_message
            .header
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_header_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Header",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_header_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let invalid_header_field_message = create_fix50sp2_new_order_single();
        let tag = 9999 as Tag;
        invalid_header_field_message
            .header
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_header_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Header FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_body<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let invalid_body_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        invalid_body_field_message
            .body
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_body_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Body",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_body_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let invalid_body_field_message = create_fix50sp2_new_order_single();
        let tag = 9999 as Tag;
        invalid_body_field_message
            .body
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_body_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Body FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_trailer<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let invalid_trailer_field_message = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        invalid_trailer_field_message
            .trailer
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_trailer_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Trailer",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_number_trailer_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let invalid_trailer_field_message = create_fix50sp2_new_order_single();
        let tag = 9999 as Tag;
        invalid_trailer_field_message
            .trailer
            .set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_trailer_field_message.build();

        ValidateTest {
            name: "Invalid Tag Number Trailer FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_not_defined_for_message<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let invalid_msg = create_fix40_new_order_single();
        let tag = 41 as Tag;
        invalid_msg.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_msg.build();

        ValidateTest {
            name: "Tag Not Defined For Message",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_NOT_DEFINED_FOR_THIS_MESSAGE_TYPE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_not_defined_for_message_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let invalid_msg = create_fix50sp2_new_order_single();
        let tag = 41 as Tag;
        invalid_msg.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = invalid_msg.build();

        ValidateTest {
            name: "Tag Not Defined For Message FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_NOT_DEFINED_FOR_THIS_MESSAGE_TYPE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_is_defined_for_message<'a>() -> ValidateTest<'a> {
        // compare to `tc_tag_is_not_defined_for_message`
        let dict = DataDictionary::parse("./spec/FIX43.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let valid_msg = create_fix43_new_order_single();
        let message_bytes = valid_msg.build();

        ValidateTest {
            name: "TagIsDefinedForMessage",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER,
            expected_ref_tag_id: None,
        }
    }

    async fn tc_tag_is_defined_for_message_fix_t<'a>() -> ValidateTest<'a> {
        // Compare to `tc_tag_is_not_defined_for_message`.
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let valid_msg = create_fix50sp2_new_order_single();
        let message_bytes = valid_msg.build();

        ValidateTest {
            name: "TagIsDefinedForMessage FIXT",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER,
            expected_ref_tag_id: None,
        }
    }

    async fn tc_field_not_found_body<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let invalid_msg1 = Message::new();
        invalid_msg1
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg1
            .header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        invalid_msg1
            .header
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(Utc::now()));

        invalid_msg1
            .trailer
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        invalid_msg1.body.set_field(11, FIXString::from("A"));
        invalid_msg1.body.set_field(21, FIXString::from("A"));
        invalid_msg1.body.set_field(55, FIXString::from("A"));
        invalid_msg1.body.set_field(54, FIXString::from("A"));
        invalid_msg1.body.set_field(38, FIXString::from("A"));

        let tag = 40 as Tag;

        // ord type is required. invalid_msg1.body.set_field(40 as Tag, "A"))
        let message_bytes = invalid_msg1.build();

        ValidateTest {
            name: "FieldNotFoundBody",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_field_not_found_body_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let invalid_msg1 = Message::new();
        invalid_msg1
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg1
            .header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIXT.1.1"));
        invalid_msg1
            .header
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        invalid_msg1
            .header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(Utc::now()));
        invalid_msg1
            .trailer
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        invalid_msg1.body.set_field(11 as Tag, FIXString::from("A"));
        invalid_msg1.body.set_field(21 as Tag, FIXString::from("A"));
        invalid_msg1.body.set_field(55 as Tag, FIXString::from("A"));
        invalid_msg1.body.set_field(54 as Tag, FIXString::from("A"));
        invalid_msg1.body.set_field(38 as Tag, FIXString::from("A"));
        invalid_msg1
            .body
            .set_field(60 as Tag, FIXUTCTimestamp::from_time(Utc::now()));
        let tag = 40 as Tag;
        // Ord type is required. invalid_msg1.body.set_field(40 as Tag, "A")).
        let message_bytes = invalid_msg1.build();

        ValidateTest {
            name: "FieldNotFoundBody FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_field_not_found_header<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);

        let invalid_msg2 = Message::new();
        invalid_msg2
            .trailer
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));

        invalid_msg2.body.set_field(11, FIXString::from("A"));
        invalid_msg2.body.set_field(21, FIXString::from("A"));
        invalid_msg2.body.set_field(55, FIXString::from("A"));
        invalid_msg2.body.set_field(54, FIXString::from("A"));
        invalid_msg2.body.set_field(38, FIXString::from("A"));

        invalid_msg2
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg2
            .header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIX.4.0"));
        invalid_msg2
            .header
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));
        // sending time is required. invalid_msg2.Header.FieldMap.set_field(tag.SendingTime, "0"))

        let tag = TAG_SENDING_TIME;
        let message_bytes = invalid_msg2.build();

        ValidateTest {
            name: "FieldNotFoundHeader",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_field_not_found_header_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));

        let invalid_msg2 = Message::new();
        invalid_msg2
            .trailer
            .set_field(TAG_CHECK_SUM, FIXString::from("000"));
        invalid_msg2.body.set_field(11 as Tag, FIXString::from("A"));
        invalid_msg2.body.set_field(21 as Tag, FIXString::from("A"));
        invalid_msg2.body.set_field(55 as Tag, FIXString::from("A"));
        invalid_msg2.body.set_field(54 as Tag, FIXString::from("A"));
        invalid_msg2.body.set_field(38 as Tag, FIXString::from("A"));

        invalid_msg2
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("D"));
        invalid_msg2
            .header
            .set_field(TAG_BEGIN_STRING, FIXString::from("FIXT.1.1"));
        invalid_msg2
            .header
            .set_field(TAG_BODY_LENGTH, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_SENDER_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_TARGET_COMP_ID, FIXString::from("0"));
        invalid_msg2
            .header
            .set_field(TAG_MSG_SEQ_NUM, FIXString::from("0"));

        // Sending time is required. invalid_msg2.Header.FieldMap.SetField(tag.SendingTime, "0")).
        let tag = TAG_SENDING_TIME;
        let message_bytes = invalid_msg2.build();

        ValidateTest {
            name: "FieldNotFoundHeader FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_REQUIRED_TAG_MISSING,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_without_a_value<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let builder = create_fix40_new_order_single();

        let bogus_tag = 109 as Tag;
        builder.body.set_field(bogus_tag, FIXString::from(""));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag SpecifiedWithoutAValue",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_WITHOUT_A_VALUE,
            expected_ref_tag_id: Some(bogus_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_without_a_value_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let builder = create_fix50sp2_new_order_single();

        let bogus_tag = 109 as Tag;
        builder.body.set_field(bogus_tag, FIXString::from(""));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag SpecifiedWithoutAValue FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_WITHOUT_A_VALUE,
            expected_ref_tag_id: Some(bogus_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_msg_type<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let builder = create_fix40_new_order_single();
        builder.header.set_field(TAG_MSG_TYPE, FIXString::from("z"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid MsgType",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_MSG_TYPE,
            expected_ref_tag_id: None,
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_msg_type_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let builder = create_fix50sp2_new_order_single();
        builder
            .header
            .set_field(TAG_MSG_TYPE, FIXString::from("zz"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid MsgType FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INVALID_MSG_TYPE,
            expected_ref_tag_id: None,
            do_not_expect_reject: false,
        }
    }

    async fn tc_value_is_incorrect<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);

        let tag = 21 as Tag;
        let builder = create_fix40_new_order_single();
        builder.body.set_field(tag, FIXString::from("4"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "ValueIsIncorrect",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_VALUE_IS_INCORRECT,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_value_is_incorrect_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));

        let tag = 21 as Tag;
        let builder = create_fix50sp2_new_order_single();
        builder.body.set_field(tag, FIXString::from("4"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "ValueIsIncorrect FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_VALUE_IS_INCORRECT,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_incorrect_data_format_for_value<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let builder = create_fix40_new_order_single();
        let tag = 38 as Tag;
        builder.body.set_field(tag, FIXString::from("+200.00"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "IncorrectDataFormatForValue",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_incorrect_data_format_for_value_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let builder = create_fix50sp2_new_order_single();
        let tag = 38 as Tag;
        builder.body.set_field(tag, FIXString::from("+200.00"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "IncorrectDataFormatForValue FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_header<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);

        let builder = create_fix40_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // should be in header
        builder.body.set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Header",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_header_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // should be in header.
        builder.body.set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Header FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_trailer<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);

        let builder = create_fix40_new_order_single();
        let tag = TAG_SIGNATURE;
        // should be in trailer
        builder.body.set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        let ref_tag = 100 as Tag;
        ValidateTest {
            name: "Tag specified out of required order in Trailer",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(ref_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_specified_out_of_required_order_trailer_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = TAG_SIGNATURE;
        // should be in trailer.
        builder.body.set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        let ref_tag = 100 as Tag;
        ValidateTest {
            name: "Tag specified out of required order in Trailer FIXT",
            validator,
            message_bytes,
            expected_reject_reason: REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER,
            expected_ref_tag_id: Some(ref_tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_invalid_tag_check_disabled<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = false;
        let validator = ValidatorEnum::new(custom_validator_settings, dict, None);

        let builder = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        builder.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid Tag Check - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_invalid_tag_check_disabled_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = false;
        let validator = ValidatorEnum::new(custom_validator_settings, app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = 9999 as Tag;
        builder.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid Tag Check - Disabled FIXT",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_invalid_tag_check_enabled<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = true;
        let validator = ValidatorEnum::new(custom_validator_settings, dict, None);

        let builder = create_fix40_new_order_single();
        let tag = 9999 as Tag;
        builder.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid Tag Check - Enabled",
            validator,
            message_bytes,
            do_not_expect_reject: false,
            expected_ref_tag_id: Some(tag),
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER, // fake reason
        }
    }

    async fn tc_invalid_tag_check_enabled_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.reject_invalid_message = true;
        let validator = ValidatorEnum::new(custom_validator_settings, app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = 9999 as Tag;
        builder.body.set_field(tag, FIXString::from("hello"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Invalid Tag Check - Enabled FIXT",
            validator,
            message_bytes,
            do_not_expect_reject: false,
            expected_ref_tag_id: Some(tag),
            expected_reject_reason: REJECT_REASON_INVALID_TAG_NUMBER, // fake reason
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_header<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = ValidatorEnum::new(custom_validator_settings, dict, None);

        let builder = create_fix40_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // should be in header
        builder.body.set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Header - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_header_fix_t<'a>() -> ValidateTest<'a>
    {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();

        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = ValidatorEnum::new(custom_validator_settings, app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = TAG_ON_BEHALF_OF_COMP_ID;
        // should be in header.
        builder.body.set_field(tag, FIXString::from("CWB"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Header - Disabled FIXT",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_trailer<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = ValidatorEnum::new(custom_validator_settings, dict, None);

        let builder = create_fix40_new_order_single();
        let tag = TAG_SIGNATURE;
        // should be in trailer
        builder.body.set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Trailer - Disabled",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_specified_out_of_required_order_disabled_trailer_fix_t<'a>() -> ValidateTest<'a>
    {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let mut custom_validator_settings = ValidatorSettings::default();
        custom_validator_settings.check_fields_out_of_order = false;
        let validator = ValidatorEnum::new(custom_validator_settings, app_dict, Some(t_dict));

        let builder = create_fix50sp2_new_order_single();
        let tag = TAG_SIGNATURE;
        // Should be in trailer.
        builder.body.set_field(tag, FIXString::from("SIG"));
        let message_bytes = builder.build();

        ValidateTest {
            name: "Tag specified out of required order in Trailer - Disabled FIXT",
            validator,
            message_bytes,
            do_not_expect_reject: true,
            expected_reject_reason: REJECT_REASON_OTHER, // fake reason
            expected_ref_tag_id: Some(666),              // fake tag
        }
    }

    async fn tc_tag_appears_more_than_once<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX40.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let tag = 40 as Tag;

        ValidateTest {
            name:  "Tag appears more than once",
            validator,
            message_bytes: "8=FIX.4.09=10735=D34=249=TW52=20060102-15:04:0556=ISLD11=ID21=140=140=254=138=20055=INTC60=20060102-15:04:0510=234".into(),
            expected_reject_reason: REJECT_REASON_TAG_APPEARS_MORE_THAN_ONCE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_tag_appears_more_than_once_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let tag = 40 as Tag;

        ValidateTest {
            name: "Tag appears more than once FIXT",
            validator,
            message_bytes: "8=FIXT.1.19=10735=D34=249=TW52=20060102-15:04:0556=ISLD11=ID21=140=140=254=138=20055=INTC60=20060102-15:04:0510=234".into(),
            expected_reject_reason: REJECT_REASON_TAG_APPEARS_MORE_THAN_ONCE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_float_validation<'a>() -> ValidateTest<'a> {
        let dict = DataDictionary::parse("./spec/FIX42.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), dict, None);
        let tag = 38 as Tag;
        ValidateTest {
            name:  "FloatValidation",
            validator,
            message_bytes: "8=FIX.4.29=10635=D34=249=TW52=20140329-22:38:4556=ISLD11=ID21=140=154=138=+200.0055=INTC60=20140329-22:38:4510=178".into(),
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id: Some(tag),
            do_not_expect_reject: false,
        }
    }

    async fn tc_float_validation_fix_t<'a>() -> ValidateTest<'a> {
        let t_dict = DataDictionary::parse("spec/FIXT11.xml").await.unwrap();
        let app_dict = DataDictionary::parse("spec/FIX50SP2.xml").await.unwrap();
        let validator = ValidatorEnum::new(ValidatorSettings::default(), app_dict, Some(t_dict));
        let tag = 38 as Tag;
        ValidateTest {
            name: "FloatValidation FIXT",
            validator,
            message_bytes: "8=FIXT.1.19=10635=D34=249=TW52=20140329-22:38:4556=ISLD11=ID21=140=154=138=+200.0055=INTC60=20140329-22:38:4510=178".into(),
            expected_reject_reason: REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE,
            expected_ref_tag_id:     Some(tag),
            do_not_expect_reject: false,
        }
    }

    #[test]
    fn test_validate_visit_field() {
        let field_type0 = FieldType::new(String::from("myfield"), 11, String::from("STRING"));
        let field_def0 = FieldDef::new(field_type0, false);

        let field_type1 = FieldType::new(String::from("myfield"), 2, String::from("STRING"));
        let field_def1 = FieldDef::new(field_type1, false);

        let field_type2 = FieldType::new(String::from("myfield"), 3, String::from("STRING"));
        let field_def2 = FieldDef::new(field_type2, false);

        let group_field_type = FieldType::new(String::from("mygroupfield"), 1, String::from("INT"));
        let mut group_field_def = FieldDef::new(group_field_type, false);
        group_field_def.fields = vec![field_def1, field_def2];

        let mut field = TagValue::default();
        field.init(11 as Tag, "value".as_bytes());

        let mut rep_field1 = TagValue::default();
        rep_field1.init(2 as Tag, "a".as_bytes());
        let mut rep_field2 = TagValue::default();
        rep_field2.init(3 as Tag, "a".as_bytes());

        let mut group_id = TagValue::default();
        group_id.init(1 as Tag, "1".as_bytes());

        let mut group_id2 = TagValue::default();
        group_id2.init(1 as Tag, "2".as_bytes());

        let mut group_id3 = TagValue::default();
        group_id3.init(1 as Tag, "3".as_bytes());

        #[derive(Default)]
        struct TestCase {
            field_def: FieldDef,
            fields: LocalField,
            expected_rem_fields: usize,
            expect_reject: bool,
            expected_reject_reason: isize,
        }
        let test_cases = vec![
            // non-repeating
            TestCase {
                expected_rem_fields: 0,
                field_def: field_def0,
                fields: LocalField::new(Arc::new(Mutex::new(vec![field.clone()]))),
                ..Default::default()
            },
            // single field group
            TestCase {
                expected_rem_fields: 0,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id.clone(),
                    rep_field1.clone(),
                ]))),
                ..Default::default()
            },
            // multiple field group
            TestCase {
                expected_rem_fields: 0,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                ]))),
                ..Default::default()
            },
            // test with trailing tag not in group
            TestCase {
                expected_rem_fields: 1,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    field.clone(),
                ]))),
                ..Default::default()
            },
            // repeats
            TestCase {
                expected_rem_fields: 1,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id2,
                    rep_field1.clone(),
                    rep_field2.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    field.clone(),
                ]))),
                ..Default::default()
            },
            // REJECT: group size declared > actual group size
            TestCase {
                expect_reject: true,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id3.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    field.clone(),
                ]))),
                expected_reject_reason:
                    REJECT_REASON_INCORRECT_NUM_IN_GROUP_COUNT_FOR_REPEATING_GROUP,
                ..Default::default()
            },
            TestCase {
                expect_reject: true,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id3.clone(),
                    rep_field1.clone(),
                    rep_field1.clone(),
                    field.clone(),
                ]))),
                expected_reject_reason:
                    REJECT_REASON_INCORRECT_NUM_IN_GROUP_COUNT_FOR_REPEATING_GROUP,
                ..Default::default()
            },
            // REJECT: group size declared < actual group size
            TestCase {
                expect_reject: true,
                field_def: group_field_def.clone(),
                fields: LocalField::new(Arc::new(Mutex::new(vec![
                    group_id.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    rep_field1.clone(),
                    rep_field2.clone(),
                    field.clone(),
                ]))),
                expected_reject_reason:
                    REJECT_REASON_INCORRECT_NUM_IN_GROUP_COUNT_FOR_REPEATING_GROUP,
                ..Default::default()
            },
        ];

        for tc in test_cases.iter() {
            let lock = tc.fields.data.lock();
            let fields = lock.get(..).unwrap();
            let validate_result = validate_visit_field(&tc.field_def, fields);

            match tc.expect_reject {
                true => {
                    assert!(validate_result.is_err(), "Expected Reject");

                    let reject = validate_result.unwrap_err();

                    assert_eq!(
                        reject.reject_reason(),
                        tc.expected_reject_reason,
                        "Expected reject reason {} got {}",
                        tc.expected_reject_reason,
                        reject.reject_reason()
                    );
                }
                false => {
                    assert!(
                        validate_result.is_ok(),
                        "Unexpected reject: {:?}",
                        validate_result,
                    );

                    let rem_fields = validate_result.unwrap();

                    assert_eq!(
                        rem_fields.len(),
                        tc.expected_rem_fields,
                        "Expected len {} got {}",
                        tc.expected_rem_fields,
                        rem_fields.len(),
                    );
                }
            }
        }
    }
}
