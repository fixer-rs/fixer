use crate::tag::Tag;
use std::string::ToString;

// TagValue is a low-level FIX field abstraction
#[derive(Default, Clone, Debug)]
pub struct TagValue {
    pub tag: Tag,
    pub value: String,
    pub bytes: String,
}

impl TagValue {
    pub fn init(tag: Tag, value: &str) -> Self {
        let mut self_value = itoa::Buffer::new().format(tag).to_string();
        self_value.push('=');
        self_value.push_str(value);
        self_value.push('');

        TagValue {
            tag,
            value: value.to_string(),
            bytes: self_value,
        }
    }

    pub fn parse(&mut self, raw_field_bytes: &str) -> Result<(), String> {
        let sep_index_option = raw_field_bytes.find('=');
        if sep_index_option.is_none() {
            return Err(format!("TagValue::parse: No '=' in '{}'", raw_field_bytes));
        }

        let sep_index = sep_index_option.unwrap();
        if sep_index == 0 {
            return Err(format!("TagValue::parse: No tag in '{}'", raw_field_bytes));
        }

        let parsed_tag_string = raw_field_bytes.get(0..sep_index).unwrap();
        let parsed_tag = parsed_tag_string
            .parse::<isize>()
            .map_err(|err| format!("TagValue::parse: {:?}", err.to_string()))?;

        self.tag = parsed_tag;
        let n = raw_field_bytes.chars().count();
        self.value = raw_field_bytes
            .get(sep_index + 1..n - 1)
            .unwrap()
            .to_string();
        self.bytes = raw_field_bytes.to_string();

        Ok(())
    }

    pub fn total(&self) -> isize {
        let mut total: isize = 0;
        for b in self.bytes.chars() {
            total += b as isize;
        }
        total
    }

    pub fn length(&self) -> isize {
        self.bytes.len() as isize
    }
}

impl ToString for TagValue {
    fn to_string(&self) -> String {
        self.bytes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_value_init() {
        let tv = TagValue::init(8, "blahblah");
        let expected_data = "8=blahblah".to_string();

        assert_eq!(
            tv.bytes, expected_data,
            "Expected {:?}, got {:?}",
            expected_data, tv.bytes,
        );

        let expected_value = "blahblah".to_string();
        assert_eq!(
            tv.value, expected_value,
            "Expected {:?}, got {:?}",
            expected_value, tv.value,
        );
    }

    #[test]
    fn test_tag_value_parse() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field);
        assert!(result.is_ok());
        assert_eq!(8, tv.tag);
        assert_eq!(tv.bytes, string_field.to_string());
        assert_eq!(tv.value, "FIX.4.0");
    }

    #[test]
    fn test_tag_value_parse_fail() {
        let mut string_field = "not_tag_equal_value";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field);
        assert!(result.is_err());

        string_field = "tag_not_an_int=uhoh";
        let result = tv.parse(string_field);
        assert!(result.is_err());

        string_field = "=notag";
        let result = tv.parse(string_field);
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_value_string() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field);
        assert!(result.is_ok());

        assert_eq!(String::from("8=FIX.4.0"), tv.to_string());
    }

    #[test]
    fn test_tag_value_length() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field);
        assert!(result.is_ok());
        assert_eq!(string_field.chars().count() as isize, tv.length());
    }

    #[test]
    fn test_tag_value_total() {
        let string_field = "1=hello";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field);
        assert!(result.is_ok());
        assert_eq!(
            643,
            tv.total(),
            "Total is the summation of the ascii byte values of the field string"
        );
    }
}
