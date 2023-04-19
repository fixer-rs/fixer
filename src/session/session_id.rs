use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    string::ToString,
};

// SessionID is a unique identifier of a Session
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
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
    // is_fixt returns true if the SessionID has a FIXT begin_string
    pub fn is_fixt(&self) -> bool {
        self.begin_string == crate::BEGIN_STRING_FIXT11
    }
}

impl ToString for SessionID {
    fn to_string(&self) -> String {
        let mut result = self.begin_string.clone();
        result.push(':');
        result.push_str(&self.sender_comp_id);

        append_optional(&mut result, "/", &self.sender_sub_id);
        append_optional(&mut result, "/", &self.sender_location_id);

        result.push_str("->");
        result.push_str(&self.target_comp_id);

        append_optional(&mut result, "/", &self.target_sub_id);
        append_optional(&mut result, "/", &self.target_location_id);

        append_optional(&mut result, ":", &self.qualifier);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_string() {
        struct TestCase {
            session_id: SessionID,
            expected_string: String,
        }
        let tests = vec![
            TestCase {
                session_id: SessionID {
                    begin_string: String::from("FIX.4.2"),
                    sender_comp_id: String::from("SND"),
                    target_comp_id: String::from("TAR"),
                    ..Default::default()
                },
                expected_string: String::from("FIX.4.2:SND->TAR"),
            },
            TestCase {
                session_id: SessionID {
                    begin_string: String::from("FIX.4.2"),
                    sender_comp_id: String::from("SND"),
                    target_comp_id: String::from("TAR"),
                    qualifier: String::from("BLAH"),
                    ..Default::default()
                },
                expected_string: String::from("FIX.4.2:SND->TAR:BLAH"),
            },
            TestCase {
                session_id: SessionID {
                    begin_string: String::from("FIX.4.2"),
                    sender_comp_id: String::from("SND"),
                    sender_sub_id: String::from("SSUB"),
                    sender_location_id: String::from("SLOC"),
                    target_comp_id: String::from("TAR"),
                    target_sub_id: String::from("TSUB"),
                    target_location_id: String::from("TLOC"),
                    qualifier: String::from("BLAH"),
                },
                expected_string: String::from("FIX.4.2:SND/SSUB/SLOC->TAR/TSUB/TLOC:BLAH"),
            },
            TestCase {
                session_id: SessionID {
                    begin_string: String::from("FIX.4.2"),
                    sender_comp_id: String::from("SND"),
                    sender_location_id: String::from("SLOC"),
                    target_comp_id: String::from("TAR"),
                    target_sub_id: String::from("TSUB"),
                    target_location_id: String::from("TLOC"),
                    ..Default::default()
                },
                expected_string: String::from("FIX.4.2:SND/SLOC->TAR/TSUB/TLOC"),
            },
        ];

        for test in tests.iter() {
            let actual = test.session_id.to_string();
            assert_eq!(test.expected_string, actual);
        }
    }
}
