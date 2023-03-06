use crate::errors::{MessageRejectError, MessageRejectErrorTrait};
use crate::tag::Tag;
use delegate::delegate;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

// IncorrectBeginString is a message reject specific to incorrect begin strings.
#[derive(Debug, Default)]
pub struct IncorrectBeginString {
    pub message_reject_error: MessageRejectError,
}

impl MessageRejectErrorTrait for IncorrectBeginString {
    delegate! {
        to self.message_reject_error {
            fn reject_reason(&self) -> isize;
            fn business_reject_ref_id(&self) -> &str;
            fn ref_tag_id(&self) -> Option<Tag>;
            fn is_business_reject(&self) -> bool;
        }
    }
}

impl Display for IncorrectBeginString {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Incorrect BeginString")
    }
}

impl Error for IncorrectBeginString {}

// TargetTooHigh is a MessageReject where the sequence number is larger than expected.
#[derive(Debug, Default)]
pub struct TargetTooHigh {
    pub message_reject_error: MessageRejectError,
    pub received_target: isize,
    pub expected_target: isize,
}

impl MessageRejectErrorTrait for TargetTooHigh {
    delegate! {
        to self.message_reject_error {
            fn reject_reason(&self) -> isize;
            fn business_reject_ref_id(&self) -> &str;
            fn ref_tag_id(&self) -> Option<Tag>;
            fn is_business_reject(&self) -> bool;
        }
    }
}

impl Display for TargetTooHigh {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "MsgSeqNum too high, expecting {} but received {}",
            self.expected_target, self.received_target
        )
    }
}

impl Error for TargetTooHigh {}

// TargetTooLow is a MessageReject where the sequence number is less than expected.
#[derive(Debug, Default)]
pub struct TargetTooLow {
    pub message_reject_error: MessageRejectError,
    pub received_target: isize,
    pub expected_target: isize,
}

impl MessageRejectErrorTrait for TargetTooLow {
    delegate! {
        to self.message_reject_error {
            fn reject_reason(&self) -> isize;
            fn business_reject_ref_id(&self) -> &str;
            fn ref_tag_id(&self) -> Option<Tag>;
            fn is_business_reject(&self) -> bool;
        }
    }
}

impl Display for TargetTooLow {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "MsgSeqNum too low, expecting {} but received {}",
            self.expected_target, self.received_target
        )
    }
}

impl Error for TargetTooLow {}
