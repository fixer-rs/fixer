use crate::tag::{Tag, TAG_BEGIN_STRING, TAG_BODY_LENGTH, TAG_MSG_TYPE};
use std::cmp::Ordering;

// in the message header, the first 3 tags in the message header must be 8,9,35
pub fn header_field_ordering(i: &Tag, j: &Tag) -> Ordering {
    fn ordering(t: &Tag) -> u32 {
        match *t {
            TAG_BEGIN_STRING => 1,
            TAG_BODY_LENGTH => 2,
            TAG_MSG_TYPE => 3,
            _ => u32::MAX,
        }
    }

    let orderi = ordering(i);
    let orderj = ordering(j);

    if orderi < orderj {
        return Ordering::Less;
    }
    if orderi > orderj {
        return Ordering::Greater;
    }

    if i < j {
        return Ordering::Less;
    }

    return Ordering::Greater;
}
