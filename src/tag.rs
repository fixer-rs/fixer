//Tag is a typed int representing a FIX tag
pub type Tag = isize;

pub trait TagTrait {
    //is_trailer returns true if tag belongs in the message trailer
    fn is_trailer(&self) -> bool;
    //is_header returns true if tag belongs in the message header
    fn is_header(&self) -> bool;
}

pub const TAG_BEGIN_STRING: Tag = 8;
pub const TAG_BODY_LENGTH: Tag = 9;
pub const TAG_MSG_TYPE: Tag = 35;
pub const TAG_SENDER_COMP_ID: Tag = 49;
pub const TAG_TARGET_COMP_ID: Tag = 56;
pub const TAG_ON_BEHALF_OF_COMP_ID: Tag = 115;
pub const TAG_DELIVER_TO_COMP_ID: Tag = 128;
pub const TAG_SECURE_DATA_LEN: Tag = 90;
pub const TAG_MSG_SEQ_NUM: Tag = 34;
pub const TAG_SENDER_SUB_ID: Tag = 50;
pub const TAG_SENDER_LOCATION_ID: Tag = 142;
pub const TAG_TARGET_SUB_ID: Tag = 57;
pub const TAG_TARGET_LOCATION_ID: Tag = 143;
pub const TAG_ON_BEHALF_OF_SUB_ID: Tag = 116;
pub const TAG_ON_BEHALF_OF_LOCATION_ID: Tag = 144;
pub const TAG_DELIVER_TO_SUB_ID: Tag = 129;
pub const TAG_DELIVER_TO_LOCATION_ID: Tag = 145;
pub const TAG_POSS_DUP_FLAG: Tag = 43;
pub const TAG_POSS_RESEND: Tag = 97;
pub const TAG_SENDING_TIME: Tag = 52;
pub const TAG_ORIG_SENDING_TIME: Tag = 122;
pub const TAG_XML_DATA_LEN: Tag = 212;
pub const TAG_XML_DATA: Tag = 213;
pub const TAG_MESSAGE_ENCODING: Tag = 347;
pub const TAG_LAST_MSG_SEQ_NUM_PROCESSED: Tag = 369;
pub const TAG_ON_BEHALF_OF_SENDING_TIME: Tag = 370;
pub const TAG_APPL_VER_ID: Tag = 1128;
pub const TAG_CSTM_APPL_VER_ID: Tag = 1129;
pub const TAG_NO_HOPS: Tag = 627;
pub const TAG_APPL_EXT_ID: Tag = 1156;
pub const TAG_SECURE_DATA: Tag = 91;
pub const TAG_HOP_COMP_ID: Tag = 628;
pub const TAG_HOP_SENDING_TIME: Tag = 629;
pub const TAG_HOP_REF_ID: Tag = 630;

pub const TAG_HEART_BT_INT: Tag = 108;
pub const TAG_BUSINESS_REJECT_REASON: Tag = 380;
pub const TAG_SESSION_REJECT_REASON: Tag = 373;
pub const TAG_REF_MSG_TYPE: Tag = 372;
pub const TAG_BUSINESS_REJECT_REF_ID: Tag = 379;
pub const TAG_REF_TAG_ID: Tag = 371;
pub const TAG_REF_SEQ_NUM: Tag = 45;
pub const TAG_ENCRYPT_METHOD: Tag = 98;
pub const TAG_RESET_SEQ_NUM_FLAG: Tag = 141;
pub const TAG_DEFAULT_APPL_VER_ID: Tag = 1137;
pub const TAG_TEXT: Tag = 58;
pub const TAG_TEST_REQ_ID: Tag = 112;
pub const TAG_GAP_FILL_FLAG: Tag = 123;
pub const TAG_NEW_SEQ_NO: Tag = 36;
pub const TAG_BEGIN_SEQ_NO: Tag = 7;
pub const TAG_END_SEQ_NO: Tag = 16;

pub const TAG_SIGNATURE_LENGTH: Tag = 93;
pub const TAG_SIGNATURE: Tag = 89;
pub const TAG_CHECK_SUM: Tag = 10;

impl TagTrait for Tag {
    fn is_trailer(&self) -> bool {
        matches!(*self, TAG_SIGNATURE_LENGTH | TAG_SIGNATURE | TAG_CHECK_SUM)
    }

    fn is_header(&self) -> bool {
        matches!(
            *self,
            TAG_BEGIN_STRING |
            TAG_BODY_LENGTH |
            TAG_MSG_TYPE |
            TAG_SENDER_COMP_ID |
            TAG_TARGET_COMP_ID |
            TAG_ON_BEHALF_OF_COMP_ID |
            TAG_DELIVER_TO_COMP_ID |
            TAG_SECURE_DATA_LEN |
            TAG_MSG_SEQ_NUM |
            TAG_SENDER_SUB_ID |
            TAG_SENDER_LOCATION_ID |
            TAG_TARGET_SUB_ID |
            TAG_TARGET_LOCATION_ID |
            TAG_ON_BEHALF_OF_SUB_ID |
            TAG_ON_BEHALF_OF_LOCATION_ID |
            TAG_DELIVER_TO_SUB_ID |
            TAG_DELIVER_TO_LOCATION_ID |
            TAG_POSS_DUP_FLAG |
            TAG_POSS_RESEND |
            TAG_SENDING_TIME |
            TAG_ORIG_SENDING_TIME |
            TAG_XML_DATA_LEN |
            TAG_XML_DATA |
            TAG_MESSAGE_ENCODING |
            TAG_LAST_MSG_SEQ_NUM_PROCESSED |
            TAG_ON_BEHALF_OF_SENDING_TIME |//IsHeader returns true if tag belongs in the message header
            TAG_APPL_VER_ID |
            TAG_CSTM_APPL_VER_ID |
            TAG_NO_HOPS |
            TAG_APPL_EXT_ID |
            TAG_SECURE_DATA |
            TAG_HOP_COMP_ID |
            TAG_HOP_SENDING_TIME |
            TAG_HOP_REF_ID
        )
    }
}
