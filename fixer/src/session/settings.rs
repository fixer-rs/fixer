use crate::errors::FixerError;
use dashmap::DashMap;
use parse_duration::parse;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;
use tokio::time::Duration;

/// Error indicating a required configuration setting is missing.
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

/// Error indicating a configuration setting has an unparseable value.
#[derive(Debug)]
pub struct IncorrectFormatForSetting {
    pub setting: String,
    pub value: String,
    pub err: Box<dyn Error + Send + Sync>,
}

impl Display for IncorrectFormatForSetting {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} is invalid for {}", self.value, self.setting)
    }
}

impl Error for IncorrectFormatForSetting {}

/// A string-keyed map of configuration values with typed accessors.
///
/// Used internally by [`Settings`](crate::settings::Settings) to represent
/// both the `[DEFAULT]` section and individual `[SESSION]` sections.
/// Values are stored as strings and parsed on demand via
/// [`int_setting`](SessionSettings::int_setting),
/// [`bool_setting`](SessionSettings::bool_setting), and
/// [`duration_setting`](SessionSettings::duration_setting).
#[derive(Default, Debug)]
pub struct SessionSettings {
    pub settings: Arc<DashMap<String, String>>,
}

impl Clone for SessionSettings {
    /// Deep-copies the settings.
    ///
    /// Not derived: the derive would clone the `Arc` and hand back a second
    /// handle onto the same map, so mutating the "copy" would mutate the
    /// original. Callers of
    /// [`Settings::global_settings`](crate::settings::Settings::global_settings)
    /// get a copy they can adjust per session without editing the engine's
    /// `[DEFAULT]` section under it.
    fn clone(&self) -> Self {
        let copy = DashMap::with_capacity(self.settings.len());
        for entry in self.settings.iter() {
            copy.insert(entry.key().clone(), entry.value().clone());
        }
        Self {
            settings: Arc::new(copy),
        }
    }
}

impl SessionSettings {
    /// Creates an empty `SessionSettings`.
    pub fn new() -> Self {
        Self {
            settings: Arc::new(DashMap::new()),
        }
    }

    /// Clears all settings.
    pub fn init(&mut self) {
        self.settings = Arc::new(DashMap::new());
    }

    /// Assigns a value to a setting key.
    pub fn set(&mut self, setting: String, val: String) {
        let _ = self.settings.insert(setting, val);
    }

    /// Returns `true` if the given key has been set.
    pub fn has_setting(&self, setting: &str) -> bool {
        self.settings.contains_key(setting)
    }

    /// Returns the raw string value of a setting, or an error if missing.
    pub fn setting(&self, setting: &str) -> Result<String, FixerError> {
        if !self.settings.contains_key(setting) {
            return Err(FixerError::new_conditionally_required(setting));
        }
        Ok(self.settings.get(setting).unwrap().to_string())
    }

    /// Returns the setting parsed as an integer, or an error if missing or
    /// unparseable.
    pub fn int_setting(&self, setting: &str) -> Result<isize, FixerError> {
        let string_val = self.setting(setting)?;

        atoi_simd::parse::<isize, false, false>(string_val.as_bytes())
            .map_err(|_| FixerError::new_incorrect_format_for_setting(setting, &string_val))
    }

    /// Returns the setting parsed as a `Duration`, or an error if missing or
    /// unparseable.
    pub fn duration_setting(&self, setting: &str) -> Result<Duration, FixerError> {
        let string_val = self.setting(setting)?;

        parse(&string_val).map_err(|err| {
            FixerError::new_incorrect_format_for_setting_with_error(
                setting,
                &string_val,
                Box::new(err),
            )
        })
    }

    /// Returns the setting parsed as a boolean (`Y`/`y` = true, `N`/`n` =
    /// false), or an error if missing or unparseable.
    pub fn bool_setting(&self, setting: &str) -> Result<bool, FixerError> {
        let string_val = self.setting(setting)?;

        match string_val.as_ref() {
            "Y" | "y" => Ok(true),
            "N" | "n" => Ok(false),
            _ => Err(FixerError::new_incorrect_format_for_setting(
                setting,
                &string_val,
            )),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    pub fn reset(&mut self) {
        self.settings.clear();
    }

    /// Copies all entries from `overlay` into this instance, overwriting
    /// existing keys.
    pub fn overlay(&mut self, overlay: &Self) {
        for entry in overlay.settings.iter() {
            let (k, v) = entry.pair();
            self.settings.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod tests {
    use crate::{config, session::settings::SessionSettings};

    #[test]
    fn test_session_settings_clone_is_independent() {
        let mut original = SessionSettings::new();
        original.set("HeartBtInt".to_string(), "30".to_string());

        let mut copy = original.clone();
        copy.set("HeartBtInt".to_string(), "60".to_string());
        copy.set("ResetOnLogon".to_string(), "Y".to_string());

        // Clone deep-copies: the two must not share a map. A derived Clone
        // would alias the Arc and let the copy edit the original.
        assert_eq!("30", original.setting("HeartBtInt").unwrap());
        assert!(!original.has_setting("ResetOnLogon"));
        assert_eq!("60", copy.setting("HeartBtInt").unwrap());

        // ...and the other direction.
        original.set("HeartBtInt".to_string(), "45".to_string());
        assert_eq!("60", copy.setting("HeartBtInt").unwrap());
    }

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
            &1005_isize,
            "Expected {}, got {:?}",
            1005,
            err.as_ref()
        );
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

        let tests = [TestCase {
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
            }];

        for test in &tests {
            s.set(config::RESET_ON_LOGON.to_string(), test.input.to_string());
            let err = s.bool_setting(config::RESET_ON_LOGON);
            assert!(err.is_ok(), "Unexpected err {err:?}");
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

        let tests = [TestCase {
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
            }];

        for test in &tests {
            s.set(test.input.to_string(), test.expected.to_string());
        }

        for test in &tests {
            let err = &s.setting(test.input);
            assert!(err.is_ok(), "Unexpected err {err:?}");
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

        let tests = [TestCase {
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
            }];

        s.overlay(&overlay);

        for test in &tests {
            let err = s.setting(test.input);
            assert!(err.is_ok(), "Unexpected err {err:?}");
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
