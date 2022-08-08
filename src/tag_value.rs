use crate::tag::Tag;
use std::string::ToString;

// TagValue is a low-level FIX field abstraction
#[derive(Default)]
pub struct TagValue {
    pub tag: Tag,
    pub value: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl TagValue {
    pub fn init(&mut self, tag: Tag, value: Vec<u8>) {
        let value_array = String::from_utf8_lossy(&value);

        let mut self_value = format!("{}", tag);
        self_value.push('=');
        self_value.push_str(&value_array);
        self_value.push('');

        self.bytes = self_value.into_bytes();
        self.tag = tag;
        self.value = value;
    }

    pub fn parse(&mut self, raw_field_bytes: Vec<u8>) -> Result<(), String> {
        let field_string = String::from_utf8_lossy(&raw_field_bytes);
        let sep_index_option = field_string.find('=');
        if sep_index_option.is_none() {
            return Err(format!("TagValue::parse: No '=' in '{:?}'", field_string));
        }

        let sep_index = sep_index_option.unwrap();
        if sep_index == 0 {
            return Err(format!("TagValue::parse: No tag in '{:?}'", field_string));
        }

        let parsed_tag_string = field_string.get(0..sep_index).unwrap();
        let parsed_tag = parsed_tag_string
            .parse::<isize>()
            .map_err(|err| format!("TagValue::parse: {:?}", err.to_string()))?;

        self.tag = parsed_tag as Tag;
        let n = field_string.chars().count();
        self.value = field_string
            .get(sep_index + 1..n - 1)
            .unwrap()
            .as_bytes()
            .to_vec();
        self.bytes = field_string.as_bytes().to_vec();

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
        let bytes = self.bytes.clone();
        String::from_utf8_lossy(&bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_value_init() {
        let mut tv = TagValue::default();

        tv.init(8 as Tag, "blahblah".as_bytes().to_vec());
        let expected_data = "8=blahblah".as_bytes().to_vec();

        assert_eq!(
            tv.bytes, expected_data,
            "Expected {:?}, got {:?}",
            expected_data, tv.bytes,
        );

        let expected_value = "blahblah".as_bytes().to_vec();
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
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_ok());
        assert_eq!(8 as Tag, tv.tag);
        assert_eq!(tv.bytes, string_field.as_bytes().to_vec());
        assert_eq!(tv.value, "FIX.4.0".as_bytes().to_vec());
    }

    #[test]
    fn test_tag_value_parse_fail() {
        let mut string_field = "not_tag_equal_value";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_err());

        string_field = "tag_not_an_int=uhoh";
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_err());

        string_field = "=notag";
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_value_string() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_ok());

        assert_eq!(String::from("8=FIX.4.0"), tv.to_string());
    }

    #[test]
    fn test_tag_value_length() {
        let string_field = "8=FIX.4.0";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_ok());
        assert_eq!(string_field.chars().count() as isize, tv.length());
    }

    #[test]
    fn test_tag_value_total() {
        let string_field = "1=hello";
        let mut tv = TagValue::default();
        let result = tv.parse(string_field.as_bytes().to_vec());
        assert!(result.is_ok());
        assert_eq!(
            643,
            tv.total(),
            "Total is the summation of the ascii byte values of the field string"
        );
    }
}
