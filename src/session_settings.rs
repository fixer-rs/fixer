use atoi::FromRadix10;
use parse_duration::parse;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use tokio::time::Duration;

// ConditionallyRequiredSetting indicates a missing setting
#[derive(Debug)]
pub struct ConditionallyRequiredSetting {
    pub setting: String,
}

impl Display for ConditionallyRequiredSetting {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Conditionally Required Setting: {}", self.setting)
    }
}

impl Error for ConditionallyRequiredSetting {}

// IncorrectFormatForSetting indicates a setting that is incorrectly formatted
#[derive(Debug)]
pub struct IncorrectFormatForSetting {
    pub setting: String,
    pub value: String,
    pub err: Box<dyn Error>,
}

impl Display for IncorrectFormatForSetting {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} is invalid for {}", self.value, self.setting)
    }
}

impl Error for IncorrectFormatForSetting {}

// SessionSettings maps session settings to values with typed accessors.
#[derive(Default, Clone)]
pub struct SessionSettings {
    settings: HashMap<String, String>,
}

impl SessionSettings {
    // new returns a newly initialized SessionSettings instance
    pub fn new() -> Self {
        SessionSettings {
            settings: hashmap! {},
        }
    }

    // init resets SessionSettings
    pub fn init(&mut self) {
        self.settings = hashmap! {};
    }

    // set assigns a value to a setting on SessionSettings.
    pub fn set(&mut self, setting: String, val: String) {
        let _ = self.settings.insert(setting, val);
    }

    // has_setting returns true if a setting is set, false if not
    pub fn has_setting(&self, setting: &str) -> bool {
        self.settings.contains_key(setting)
    }

    // setting is a settings string accessor. Returns an error if the setting is missing.
    pub fn setting(&self, setting: &str) -> Result<String, Box<dyn Error>> {
        if !self.settings.contains_key(setting) {
            return Err(Box::new(ConditionallyRequiredSetting {
                setting: setting.to_string(),
            }));
        }
        Ok(self.settings.get(setting).unwrap().to_string())
    }

    // int_setting returns the requested setting parsed as an int.  Returns an errror if the setting is not set or cannot be parsed as an int.
    pub fn int_setting(&self, setting: &str) -> Result<isize, Box<dyn Error>> {
        let string_val = self.setting(setting)?;

        let (value, dgt) = isize::from_radix_10(string_val.as_bytes());

        if value == 0 && dgt == 0 {
            return Err(Box::new(IncorrectFormatForSetting {
                setting: setting.to_string(),
                value: string_val,
                err: Box::new(simple_error!("invalid setting")),
            }));
        }

        Ok(value)
    }

    // duration_setting returns the requested setting parsed as a Duration.
    // Returns an error if the setting is not set or cannot be parsed as a time.Duration.
    pub fn duration_setting(&self, setting: &str) -> Result<Duration, Box<dyn Error>> {
        let string_val = self.setting(setting)?;

        let val_result = parse(&string_val);
        if val_result.is_err() {
            return Err(Box::new(IncorrectFormatForSetting {
                setting: setting.to_string(),
                value: string_val,
                err: Box::new(val_result.unwrap_err()),
            }));
        }
        Ok(val_result.unwrap())
    }

    // bool_setting returns the requested setting parsed as a boolean.  Returns an error if the setting is not set or cannot be parsed as a bool.
    pub fn bool_setting(&self, setting: &str) -> Result<bool, Box<dyn Error>> {
        let string_val = self.setting(setting)?;

        match string_val.as_ref() {
            "Y" | "y" => Ok(true),
            "N" | "n" => Ok(false),
            _ => Err(Box::new(IncorrectFormatForSetting {
                setting: setting.to_string(),
                value: string_val,
                err: Box::new(simple_error!("")),
            })),
        }
    }

    fn overlay(&mut self, overlay: &SessionSettings) {
        for (k, v) in overlay.settings.iter() {
            let _ = self.settings.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn test_session_settings_string_settings() {
        let mut s = SessionSettings::new();

        s.set(config::BEGIN_STRING.to_string(), "foo".to_string());
        s.set(config::BEGIN_STRING.to_string(), "blah".to_string());
        s.set(config::SENDER_COMP_ID.to_string(), "bar".to_string());

        let ok = s.has_setting("DoesNotExist");
        assert!(
            !ok,
            "HasSetting returned true for setting that doesn't exist"
        );

        let ok = s.has_setting(config::BEGIN_STRING);
        assert!(ok, "HasSetting returned false for setting that does exist");

        let val = s.setting(config::BEGIN_STRING);
        assert!(
            val.is_ok(),
            "Got error requesing setting: {:?}",
            val.as_ref()
        );
        assert_eq!(
            val.as_ref().unwrap(),
            "blah",
            "Expected {} got {:?}",
            "blah",
            val.as_ref(),
        );
    }

    #[test]
    fn test_session_settings_int_settings() {
        let mut s = SessionSettings::new();
        let err = s.int_setting(config::SOCKET_ACCEPT_PORT);
        assert!(err.is_err(), "Expected error for unknown setting");

        s.set(
            config::SOCKET_ACCEPT_PORT.to_string(),
            "notanint".to_string(),
        );
        let err = s.int_setting(config::SOCKET_ACCEPT_PORT);
        assert!(err.is_err(), "Expected error for unparsable value");

        s.set(config::SOCKET_ACCEPT_PORT.to_string(), "1005".to_string());
        let err = s.int_setting(config::SOCKET_ACCEPT_PORT);
        assert!(
            err.is_ok(),
            "Unexpected err {:?}",
            err.as_ref().unwrap_err()
        );
        assert_eq!(
            err.as_ref().unwrap(),
            &(1005 as isize),
            "Expected {}, got {:?}",
            1005,
            err.as_ref()
        )
    }

    #[test]
    fn test_session_settings_bool_settings() {
        let mut s = SessionSettings::new();
        let err = s.bool_setting(config::RESET_ON_LOGON);
        assert!(err.is_err(), "Expected error for unknown setting");

        s.set(config::RESET_ON_LOGON.to_string(), "notabool".to_string());
        let err = s.bool_setting(config::RESET_ON_LOGON);
        assert!(err.is_err(), "Expected error for unparsable value");

        struct TestCase<'a> {
            input: &'a str,
            expected: bool,
        }

        let tests = vec![
            TestCase {
                input: "Y",
                expected: true,
            },
            TestCase {
                input: "y",
                expected: true,
            },
            TestCase {
                input: "N",
                expected: false,
            },
            TestCase {
                input: "n",
                expected: false,
            },
        ];

        for test in tests.iter() {
            s.set(config::RESET_ON_LOGON.to_string(), test.input.to_string());
            let err = s.bool_setting(config::RESET_ON_LOGON);
            assert!(err.is_ok(), "Unexpected err {:?}", err);
            assert_eq!(
                err.as_ref().unwrap(),
                &test.expected,
                "Expected {}, got {:?}",
                test.expected,
                err.as_ref()
            );
        }
    }

    #[test]
    fn test_session_settings_clone() {
        let mut s = SessionSettings::new();

        struct TestCase<'a> {
            input: &'a str,
            expected: &'a str,
        }

        let tests = vec![
            TestCase {
                input: config::SOCKET_ACCEPT_PORT,
                expected: "101",
            },
            TestCase {
                input: config::BEGIN_STRING,
                expected: "foo",
            },
            TestCase {
                input: config::RESET_ON_LOGON,
                expected: "N",
            },
        ];

        for test in tests.iter() {
            s.set(test.input.to_string(), test.expected.to_string());
        }

        let cloned = s.clone();

        for test in tests.iter() {
            let err = cloned.setting(test.input);
            assert!(err.is_ok(), "Unexpected err {:?}", err);
            assert_eq!(
                test.expected,
                err.as_ref().unwrap(),
                "Expected {}, got {:?}",
                test.expected,
                err.as_ref()
            );
        }
    }

    #[test]
    fn test_session_settings_overlay() {
        let mut s = SessionSettings::new();
        let mut overlay = SessionSettings::new();

        s.set(config::SOCKET_ACCEPT_PORT.to_string(), "101".to_string());
        s.set(config::BEGIN_STRING.to_string(), "foo".to_string());

        overlay.set(config::SOCKET_ACCEPT_PORT.to_string(), "102".to_string());
        overlay.set(config::SENDER_COMP_ID.to_string(), "blah".to_string());

        struct TestCase<'a> {
            input: &'a str,
            expected: &'a str,
        }

        let tests = vec![
            TestCase {
                input: config::SOCKET_ACCEPT_PORT,
                expected: "102",
            },
            TestCase {
                input: config::BEGIN_STRING,
                expected: "foo",
            },
            TestCase {
                input: config::SENDER_COMP_ID,
                expected: "blah",
            },
        ];

        s.overlay(&overlay);

        for test in tests.iter() {
            let err = s.setting(test.input);
            assert!(err.is_ok(), "Unexpected err {:?}", err);
            assert_eq!(
                test.expected,
                err.as_ref().unwrap(),
                "Expected {}, got {:?}",
                test.expected,
                err.as_ref()
            );
        }
    }
}
