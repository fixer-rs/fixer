use crate::tag::Tag;
use simple_error::SimpleError;
use std::error::Error;
use std::fmt::{Display, Formatter, Result};

lazy_static! {
    // ERR_DO_NOT_SEND is a convenience error to indicate a DoNotSend in ToApp
    static ref ERR_DO_NOT_SEND: SimpleError = simple_error!("Do Not Send");
}

const REJECT_REASON_INVALID_TAG_NUMBER: i32 = 0;
const REJECT_REASON_REQUIRED_TAG_MISSING: i32 = 1;
const REJECT_REASON_TAG_NOT_DEFINED_FOR_THIS_MESSAGE_TYPE: i32 = 2;
const REJECT_REASON_UNSUPPORTED_MESSAGE_TYPE: i32 = 3;
const REJECT_REASON_TAG_SPECIFIED_WITHOUT_A_VALUE: i32 = 4;
const REJECT_REASON_VALUE_IS_INCORRECT: i32 = 5;
const REJECT_REASON_CONDITIONALLY_REQUIRED_FIELD_MISSING: i32 = 5;
const REJECT_REASON_INCORRECT_DATA_FORMAT_FOR_VALUE: i32 = 6;
const REJECT_REASON_COMP_ID_PROBLEM: i32 = 9;
const REJECT_REASON_SENDING_TIME_ACCURACY_PROBLEM: i32 = 10;
const REJECT_REASON_INVALID_MSG_TYPE: i32 = 11;
const REJECT_REASON_TAG_APPEARS_MORE_THAN_ONCE: i32 = 13;
const REJECT_REASON_TAG_SPECIFIED_OUT_OF_REQUIRED_ORDER: i32 = 14;
const REJECT_REASON_REPEATING_GROUP_FIELDS_OUT_OF_ORDER: i32 = 15;
const REJECT_REASON_INCORRECT_NUM_IN_GROUP_COUNT_FOR_REPEATING_GROUP: i32 = 16;

// MessageRejectError is a type of error that can correlate to a message reject.
pub trait MessageRejectErrorTrait: Error {
    // RejectReason, tag 373 for session rejects, tag 380 for business rejects.
    fn reject_reason() -> isize;
    fn business_reject_ref_id() -> String;
    fn ref_tag_id() -> Option<Tag>;
    fn is_business_reject() -> bool;
}

// RejectLogon indicates the application is rejecting permission to logon. Implements MessageRejectError
#[derive(Debug)]
pub struct RejectLogon {
    pub text: String,
}

impl Display for RejectLogon {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.text)
    }
}

impl Error for RejectLogon {
    fn description(&self) -> &str {
        &self.text
    }
}

impl MessageRejectErrorTrait for RejectLogon {
    // reject_reason implements MessageRejectError
    fn reject_reason() -> isize {
        0
    }

    // business_reject_ref_id implements MessageRejectError
    fn business_reject_ref_id() -> String {
        String::from("")
    }

    // ref_tag_id implements MessageRejectError
    fn ref_tag_id() -> Option<Tag> {
        None
    }

    // is_business_reject implements MessageRejectError
    fn is_business_reject() -> bool {
        false
    }
}

struct MessageRejectError {
    reject_reason: isize,
    text: String,
    business_reject_ref_id: String,
    ref_tag_id: Option<Tag>,
    is_business_reject: bool,
}

// func (e messageRejectError) Error() string               { return e.text }
// func (e messageRejectError) RefTagID() *Tag              { return e.refTagID }
// func (e messageRejectError) RejectReason() int           { return e.rejectReason }
// func (e messageRejectError) BusinessRejectRefID() string { return e.businessRejectRefID }
// func (e messageRejectError) IsBusinessReject() bool      { return e.isBusinessReject }

// //NewMessageRejectError returns a MessageRejectError with the given error message, reject reason, and optional reftagid
// func NewMessageRejectError(err string, rejectReason int, refTagID *Tag) MessageRejectError {
// 	return messageRejectError{text: err, rejectReason: rejectReason, refTagID: refTagID}
// }

// //NewBusinessMessageRejectError returns a MessageRejectError with the given error mesage, reject reason, and optional reftagid.
// //Reject is treated as a business level reject
// func NewBusinessMessageRejectError(err string, rejectReason int, refTagID *Tag) MessageRejectError {
// 	return messageRejectError{text: err, rejectReason: rejectReason, refTagID: refTagID, isBusinessReject: true}
// }

// //NewBusinessMessageRejectErrorWithRefID returns a MessageRejectError with the given error mesage, reject reason, refID, and optional reftagid.
// //Reject is treated as a business level reject
// func NewBusinessMessageRejectErrorWithRefID(err string, rejectReason int, businessRejectRefID string, refTagID *Tag) MessageRejectError {
// 	return messageRejectError{text: err, rejectReason: rejectReason, refTagID: refTagID, businessRejectRefID: businessRejectRefID, isBusinessReject: true}
// }

// //IncorrectDataFormatForValue returns an error indicating a field that cannot be parsed as the type required.
// func IncorrectDataFormatForValue(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Incorrect data format for value", rejectReasonIncorrectDataFormatForValue, &tag)
// }

// //repeatingGroupFieldsOutOfOrder returns an error indicating a problem parsing repeating groups fields
// func repeatingGroupFieldsOutOfOrder(tag Tag, reason string) MessageRejectError {
// 	if reason != "" {
// 		reason = fmt.Sprintf("Repeating group fields out of order (%s)", reason)
// 	} else {
// 		reason = "Repeating group fields out of order"
// 	}
// 	return NewMessageRejectError(reason, rejectReasonRepeatingGroupFieldsOutOfOrder, &tag)
// }

// //ValueIsIncorrect returns an error indicating a field with value that is not valid.
// func ValueIsIncorrect(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Value is incorrect (out of range) for this tag", rejectReasonValueIsIncorrect, &tag)
// }

// //ConditionallyRequiredFieldMissing indicates that the requested field could not be found in the FIX message.
// func ConditionallyRequiredFieldMissing(tag Tag) MessageRejectError {
// 	return NewBusinessMessageRejectError(fmt.Sprintf("Conditionally Required Field Missing (%d)", tag), rejectReasonConditionallyRequiredFieldMissing, &tag)
// }

// //valueIsIncorrectNoTag returns an error indicating a field with value that is not valid.
// //FIXME: to be compliant with legacy tests, for certain value issues, do not include reftag? (11c_NewSeqNoLess)
// func valueIsIncorrectNoTag() MessageRejectError {
// 	return NewMessageRejectError("Value is incorrect (out of range) for this tag", rejectReasonValueIsIncorrect, nil)
// }

// //InvalidMessageType returns an error to indicate an invalid message type
// func InvalidMessageType() MessageRejectError {
// 	return NewMessageRejectError("Invalid MsgType", rejectReasonInvalidMsgType, nil)
// }

// //UnsupportedMessageType returns an error to indicate an unhandled message.
// func UnsupportedMessageType() MessageRejectError {
// 	return NewBusinessMessageRejectError("Unsupported Message Type", rejectReasonUnsupportedMessageType, nil)
// }

// //TagNotDefinedForThisMessageType returns an error for an invalid tag appearing in a message.
// func TagNotDefinedForThisMessageType(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Tag not defined for this message type", rejectReasonTagNotDefinedForThisMessageType, &tag)
// }

// //tagAppearsMoreThanOnce return an error for multiple tags in a message not detected as a repeating group.
// func tagAppearsMoreThanOnce(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Tag appears more than once", rejectReasonTagAppearsMoreThanOnce, &tag)
// }

// //RequiredTagMissing returns a validation error when a required field cannot be found in a message.
// func RequiredTagMissing(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Required tag missing", rejectReasonRequiredTagMissing, &tag)
// }

// //incorrectNumInGroupCountForRepeatingGroup returns a validation error when the num in group value for a group does not match actual group size.
// func incorrectNumInGroupCountForRepeatingGroup(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Incorrect NumInGroup count for repeating group", rejectReasonIncorrectNumInGroupCountForRepeatingGroup, &tag)
// }

// //tagSpecifiedOutOfRequiredOrder returns validation error when the group order does not match the spec.
// func tagSpecifiedOutOfRequiredOrder(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Tag specified out of required order", rejectReasonTagSpecifiedOutOfRequiredOrder, &tag)
// }

// //TagSpecifiedWithoutAValue returns a validation error for when a field has no value.
// func TagSpecifiedWithoutAValue(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Tag specified without a value", rejectReasonTagSpecifiedWithoutAValue, &tag)
// }

// //InvalidTagNumber returns a validation error for messages with invalid tags.
// func InvalidTagNumber(tag Tag) MessageRejectError {
// 	return NewMessageRejectError("Invalid tag number", rejectReasonInvalidTagNumber, &tag)
// }

// //compIDProblem creates a reject for msg where msg has invalid comp id values.
// func compIDProblem() MessageRejectError {
// 	return NewMessageRejectError("CompID problem", rejectReasonCompIDProblem, nil)
// }

// //sendingTimeAccuracyProblem creates a reject for a msg with stale or invalid sending time.
// func sendingTimeAccuracyProblem() MessageRejectError {
// 	return NewMessageRejectError("SendingTime accuracy problem", rejectReasonSendingTimeAccuracyProblem, nil)
// }
