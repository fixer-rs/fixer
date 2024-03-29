use crate::tag::Tag;
use std::string::ToString;

// TagValue is a low-level FIX field abstraction
#[derive(Default, Clone, Debug, PartialEq)]
pub struct TagValue {
    pub tag: Tag,
    pub value: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl TagValue {
    pub fn init(&mut self, tag: Tag, value: &[u8]) {
        self.bytes = itoa::Buffer::new().format(tag).as_bytes().to_vec();
        self.bytes.push(b'=');
        self.bytes.extend_from_slice(value);
        self.bytes.push(b'');

        self.tag = tag;
        self.value = value.to_vec();
    }

    pub fn parse(&mut self, raw_field_bytes: &[u8]) -> Result<(), String> {
        let sep_index_option = raw_field_bytes.iter().position(|x| '=' == *x as char);
        if sep_index_option.is_none() {
            return Err(format!(
                "TagValue::parse: No '=' in '{}'",
                String::from_utf8_lossy(raw_field_bytes)
            ));
        }

        let sep_index = sep_index_option.unwrap();
        if sep_index == 0 {
            return Err(format!(
                "TagValue::parse: No tag in '{}'",
                String::from_utf8_lossy(raw_field_bytes)
            ));
        }

        let parsed_tag_bytes = raw_field_bytes.get(0..sep_index).unwrap();
        let parsed_tag = atoi_simd::parse::<isize>(parsed_tag_bytes).map_err(|_| {
            format!(
                "tagValue.Parse: '{}'",
                String::from_utf8_lossy(parsed_tag_bytes)
            )
        })?;

        self.tag = parsed_tag;
        let n = raw_field_bytes.len();
        self.value = raw_field_bytes.get(sep_index + 1..n - 1).unwrap().to_vec();
        self.bytes = raw_field_bytes.to_vec();

        Ok(())
    }

    pub fn total(&self) -> isize {
        let mut total: isize = 0;
        for b in self.bytes.iter() {
            total += *b as isize;
        }
        total
    }

    pub fn length(&self) -> isize {
        self.bytes.len() as isize
    }
}

impl ToString for TagValue {
    fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_value_init() {
        let mut tv = TagValue::default();
        tv.init(8, "blahblah".as_bytes());
        let expected_data = "8=blahblah".as_bytes();

        assert_eq!(
            &tv.bytes, expected_data,
            "Expected {:?}, got {:?}",
            expected_data, tv.bytes,
        );

        let expected_value = "blahblah".as_bytes();
        assert_eq!(
            &tv.value, expected_value,
            "Expected {:?}, got {:?}",
            expected_value, tv.value,
        );
    }

    #[test]
    fn test_tag_value_parse() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(8, tv.tag);
        assert_eq!(tv.bytes, string_field.as_bytes());
        assert_eq!(tv.value, "FIX.4.0".as_bytes());
    }

    #[test]
    fn test_tag_value_parse_fail() {
        let mut string_field = "not_tag_equal_value";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());

        string_field = "tag_not_an_int=uhoh";
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());

        string_field = "=notag";
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_value_string() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());

        assert_eq!(String::from("8=FIX.4.0"), tv.to_string());
    }

    #[test]
    fn test_tag_value_length() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(string_field.chars().count() as isize, tv.length());
    }

    #[test]
    fn test_tag_value_total() {
        let string_field = "1=hello";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes());
        assert!(result.is_ok());
        assert_eq!(
            643,
            tv.total(),
            "Total is the summation of the ascii byte values of the field string"
        );
    }
}
