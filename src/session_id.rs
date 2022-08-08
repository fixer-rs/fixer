// SessionID is a unique identifier of a Session
pub struct SessionID {
    pub begin_string: String,
    pub target_comp_id: String,
    pub target_sub_id: String,
    pub target_location_id: String,
    pub sender_comp_id: String,
    pub sender_sub_id: String,
    pub sender_location_id: String,
    pub qualifier: String,
}

fn append_optional(buffer: &mut String, delim: &str, v: &str) {
    if v.is_empty() {
        return;
    }

    buffer.push_str(delim);
    buffer.push_str(v);
}

impl SessionID {
    // is_fixt returns true if the SessionID has a FIXT BeginString
    pub fn is_fixt(&self) -> bool {
        self.begin_string == crate::BEGIN_STRING_FIXT11
    }
}
