use crate::{
    config::{
        BEGIN_STRING, SENDER_COMP_ID, SENDER_LOCATION_ID, SENDER_SUB_ID, SESSION_QUALIFIER,
        TARGET_COMP_ID, TARGET_LOCATION_ID, TARGET_SUB_ID,
    },
    session::{session_id::SessionID, session_settings::SessionSettings},
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
    BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use std::{collections::HashMap, error::Error};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    sync::RwLock,
};

pub static BLANK_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*$").unwrap());
pub static COMMENT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^#.*").unwrap());
pub static DEFAULT_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[(?i)DEFAULT\]\s*$").unwrap());
pub static SESSION_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\[(?i)SESSION\]\s*$").unwrap());
pub static SETTING_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([^=]*)=(.*)$").unwrap());

// The Settings type represents a collection of global and session settings.
#[derive(Default, Debug)]
pub struct Settings {
    global_settings: Arc<RwLock<Option<SessionSettings>>>,
    session_settings: HashMap<Arc<SessionID>, SessionSettings>, // TODO: convert this to &SessionID
}

impl Settings {
    // new creates a Settings instance.
    pub fn new() -> Self {
        let mut s = Self::default();
        s.init();
        s
    }

    fn init(&mut self) {
        self.global_settings = Arc::new(RwLock::new(Some(SessionSettings::new())));
        self.session_settings.clear();
    }

    async fn lazy_init(&mut self) {
        if self.global_settings.read().await.is_none() {
            self.init()
        }
    }

    // parse creates and initializes a Settings instance with config parsed from a Reader.
    // Returns error if the config is has parse errors.
    pub async fn parse<F>(reader: F) -> Result<Self, Box<dyn Error + Send + Sync>>
    where
        F: AsyncBufRead,
    {
        let mut s = Settings::new();

        let mut settings: Arc<RwLock<Option<SessionSettings>>> = Arc::new(RwLock::new(None));

        let mut line_number = 0;

        let mut lines = Box::pin(reader).lines();

        while let Some(line) = lines.next_line().await? {
            line_number += 1;

            if COMMENT_REGEX.is_match(&line) || BLANK_REGEX.is_match(&line) {
                continue;
            } else if DEFAULT_REGEX.is_match(&line) {
                settings = s.global_settings().await;
            } else if SESSION_REGEX.is_match(&line) {
                if settings.read().await.is_some()
                    && settings.read().await.as_ref().unwrap()
                        != s.global_settings().await.read().await.as_ref().unwrap()
                {
                    s.add_session(settings.read().await.clone().unwrap())
                        .await?;
                }
                settings = Arc::new(RwLock::new(Some(SessionSettings::new())));
            } else if SETTING_REGEX.is_match(&line) {
                let parts = SETTING_REGEX
                    .captures(&line)
                    .ok_or(simple_error!("error parsing line: {}", line_number))?;

                if parts.len() != 3 {
                    return Err(simple_error!("error parsing line: {}", line_number).into());
                }

                let key = parts.get(1).map(|m| m.as_str()).unwrap();
                let val = parts.get(2).map(|m| m.as_str()).unwrap();

                settings
                    .write()
                    .await
                    .as_mut()
                    .unwrap()
                    .set(key.to_string(), val.to_string());
            } else {
                return Err(simple_error!("error parsing line: {}", line_number).into());
            }
        }

        if settings.read().await.is_none()
            || settings.read().await.as_ref().unwrap()
                == s.global_settings().await.read().await.as_ref().unwrap()
        {
            return Err(simple_error!("no sessions declared").into());
        }

        let _ = s
            .add_session(settings.read().await.clone().unwrap())
            .await?;
        Ok(s)
    }

    // global_settings are default setting inherited by all session settings.
    pub async fn global_settings(&mut self) -> Arc<RwLock<Option<SessionSettings>>> {
        self.lazy_init().await;
        self.global_settings.clone()
    }

    // session_settings return all session settings overlaying globalsettings.
    pub async fn session_settings(&self) -> HashMap<Arc<SessionID>, SessionSettings> {
        let mut all_session_settings = hashmap! {};

        for (session_id, settings) in &self.session_settings {
            let global_clone = self.global_settings.clone();
            let mut clone_settings = global_clone.read().await.as_ref().unwrap().clone();

            clone_settings.overlay(&settings);
            all_session_settings.insert(session_id.clone(), clone_settings);
        }

        all_session_settings
    }

    // add_session adds Session Settings to Settings instance. Returns an error if session settings with duplicate sessionID has already been added.
    pub async fn add_session(
        &mut self,
        session_settings: SessionSettings,
    ) -> Result<Arc<SessionID>, Box<dyn Error + Send + Sync>> {
        self.lazy_init().await;
        let session_id = session_id_from_session_settings(
            &self.global_settings().await.read().await.as_ref().unwrap(),
            &session_settings,
        );

        match session_id.begin_string.as_str() {
            BEGIN_STRING_FIX40 | BEGIN_STRING_FIX41 | BEGIN_STRING_FIX42 | BEGIN_STRING_FIX43
            | BEGIN_STRING_FIX44 | BEGIN_STRING_FIXT11 => {}
            _ => {
                return Err(
                    simple_error!("BeginString must be FIX.4.0 to FIX.4.4 or FIXT.1.1").into(),
                );
            }
        }

        if self.session_settings.contains_key(&session_id) {
            return Err(simple_error!(
                "duplicate session configured for {}",
                &session_id.to_string()
            )
            .into());
        }

        self.session_settings
            .insert(session_id.clone(), session_settings);

        Ok(session_id)
    }
}

fn session_id_from_session_settings(
    global_settings: &SessionSettings,
    session_settings: &SessionSettings,
) -> Arc<SessionID> {
    let mut session_id = SessionID::default();

    for settings in vec![global_settings, session_settings] {
        if settings.has_setting(BEGIN_STRING) {
            session_id.begin_string = settings.setting(BEGIN_STRING).unwrap();
        }

        if settings.has_setting(TARGET_COMP_ID) {
            session_id.target_comp_id = settings.setting(TARGET_COMP_ID).unwrap();
        }

        if settings.has_setting(TARGET_SUB_ID) {
            session_id.target_sub_id = settings.setting(TARGET_SUB_ID).unwrap();
        }

        if settings.has_setting(TARGET_LOCATION_ID) {
            session_id.target_location_id = settings.setting(TARGET_LOCATION_ID).unwrap();
        }

        if settings.has_setting(SENDER_COMP_ID) {
            session_id.sender_comp_id = settings.setting(SENDER_COMP_ID).unwrap();
        }

        if settings.has_setting(SENDER_SUB_ID) {
            session_id.sender_sub_id = settings.setting(SENDER_SUB_ID).unwrap();
        }

        if settings.has_setting(SENDER_LOCATION_ID) {
            session_id.sender_location_id = settings.setting(SENDER_LOCATION_ID).unwrap();
        }

        if settings.has_setting(SESSION_QUALIFIER) {
            session_id.qualifier = settings.setting(SESSION_QUALIFIER).unwrap();
        }
    }

    Arc::new(session_id)
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{
            BEGIN_STRING, RESET_ON_LOGON, SENDER_COMP_ID, SESSION_QUALIFIER, SOCKET_ACCEPT_PORT,
            TARGET_COMP_ID,
        },
        session::{session_id::SessionID, session_settings::SessionSettings},
        settings::{session_id_from_session_settings, Settings},
        BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
        BEGIN_STRING_FIX44, BEGIN_STRING_FIXT11,
    };
    use std::sync::Arc;

    struct SettingsAddSessionSuite {
        settings: Settings,
    }

    fn setup_test() -> SettingsAddSessionSuite {
        SettingsAddSessionSuite {
            settings: Settings::new(),
        }
    }

    #[tokio::test]
    async fn test_settings_new() {
        let mut s = Settings::new();

        let global_settings = s.global_settings().await;
        assert!(global_settings.read().await.is_some());

        let session_settings = s.session_settings().await;
        assert!(session_settings.is_empty());
    }

    #[tokio::test]
    async fn test_begin_string_validation() {
        let mut ss = SessionSettings::new();
        ss.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        ss.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let mut s = setup_test();
        let res = s.settings.add_session(ss.clone()).await;
        assert!(res.is_err());

        ss.set(BEGIN_STRING.to_string(), "NotAValidBeginString".to_string());
        let res = s.settings.add_session(ss.clone()).await;
        assert!(res.is_err());

        let cases = vec![
            BEGIN_STRING_FIX40,
            BEGIN_STRING_FIX41,
            BEGIN_STRING_FIX42,
            BEGIN_STRING_FIX43,
            BEGIN_STRING_FIX44,
            BEGIN_STRING_FIXT11,
        ];
        for begin_str in cases.iter() {
            ss.set(BEGIN_STRING.to_string(), begin_str.to_string());
            let res = s.settings.add_session(ss.clone()).await;
            assert!(res.is_ok());
            let sid = res.unwrap();
            assert_eq!(
                *sid,
                SessionID {
                    begin_string: begin_str.to_string(),
                    sender_comp_id: "CB".to_string(),
                    target_comp_id: "SS".to_string(),
                    ..Default::default()
                }
            )
        }
    }

    #[tokio::test]
    async fn test_global_overlay() {
        let mut s = setup_test();
        let global_settings = s.settings.global_settings().await;
        global_settings
            .write()
            .await
            .as_mut()
            .unwrap()
            .set(BEGIN_STRING.to_string(), "FIX.4.0".to_string());
        global_settings
            .write()
            .await
            .as_mut()
            .unwrap()
            .set(SOCKET_ACCEPT_PORT.to_string(), "1000".to_string());

        let mut s1 = SessionSettings::new();
        s1.set(BEGIN_STRING.to_string(), "FIX.4.1".to_string());
        s1.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        s1.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let mut s2 = SessionSettings::new();
        s2.set(RESET_ON_LOGON.to_string(), "Y".to_string());
        s2.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        s2.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let session_id1 = SessionID {
            begin_string: "FIX.4.1".to_string(),
            sender_comp_id: "CB".to_string(),
            target_comp_id: "SS".to_string(),
            ..Default::default()
        };
        let session_id2 = SessionID {
            begin_string: "FIX.4.0".to_string(),
            sender_comp_id: "CB".to_string(),
            target_comp_id: "SS".to_string(),
            ..Default::default()
        };

        struct TestCase {
            settings: SessionSettings,
            expected_session_id: SessionID,
        }

        let tests = vec![
            TestCase {
                settings: s1,
                expected_session_id: session_id1.clone(),
            },
            TestCase {
                settings: s2,
                expected_session_id: session_id2.clone(),
            },
        ];

        for test in tests.iter() {
            let sid_result = s.settings.add_session(test.settings.clone()).await;
            assert!(sid_result.is_ok());
            assert_eq!(*sid_result.unwrap(), test.expected_session_id);
        }

        let arc_session_id1 = Arc::new(session_id1);
        let arc_session_id2 = Arc::new(session_id2);

        struct Case<'a> {
            session_id: Arc<SessionID>,
            input: &'a str,
            expected: &'a str,
        }

        let cases = vec![
            Case {
                session_id: arc_session_id1.clone(),
                input: BEGIN_STRING,
                expected: "FIX.4.1",
            },
            Case {
                session_id: arc_session_id1.clone(),
                input: SOCKET_ACCEPT_PORT,
                expected: "1000",
            },
            Case {
                session_id: arc_session_id2.clone(),
                input: BEGIN_STRING,
                expected: "FIX.4.0",
            },
            Case {
                session_id: arc_session_id2.clone(),
                input: SOCKET_ACCEPT_PORT,
                expected: "1000",
            },
            Case {
                session_id: arc_session_id2.clone(),
                input: RESET_ON_LOGON,
                expected: "Y",
            },
        ];

        let session_settings = s.settings.session_settings().await;
        assert_eq!(session_settings.len(), 2);

        for tc in cases.iter() {
            let settings_result = session_settings.get(&tc.session_id);
            assert!(settings_result.is_some());
            let settings = settings_result.unwrap();

            let actual_result = settings.setting(tc.input);
            assert!(actual_result.is_ok());
            assert_eq!(actual_result.unwrap(), tc.expected);
        }
    }

    #[tokio::test]
    async fn test_reject_duplicate() {
        let mut s = setup_test();

        let mut s1 = SessionSettings::new();
        s1.set(BEGIN_STRING.to_string(), "FIX.4.1".to_string());
        s1.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        s1.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let mut s2 = SessionSettings::new();
        s2.set(BEGIN_STRING.to_string(), "FIX.4.0".to_string());
        s2.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        s2.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let add_result = s.settings.add_session(s1.clone()).await;
        assert!(add_result.is_ok());
        let add_result = s.settings.add_session(s2.clone()).await;
        assert!(add_result.is_ok());

        let mut s3 = SessionSettings::new();
        s3.set(BEGIN_STRING.to_string(), "FIX.4.0".to_string());
        s3.set(SENDER_COMP_ID.to_string(), "CB".to_string());
        s3.set(TARGET_COMP_ID.to_string(), "SS".to_string());

        let add_result = s.settings.add_session(s3.clone()).await;
        assert!(
            add_result.is_err(),
            "Expected error for adding duplicate session"
        );

        let session_settings = s.settings.session_settings().await;
        assert_eq!(session_settings.len(), 2);
    }

    #[tokio::test]
    async fn test_settings_parse_settings() {
        let cfg = r#"
# default settings for sessions
[DEFAULT]
ConnectionType=initiator
ReconnectInterval=60
SenderCompID=TW


# session definition
[SESSION]
# inherit ConnectionType, ReconnectInterval and SenderCompID from default

BeginString=FIX.4.1
TargetCompID=ARCA
StartTime=12:30:00
EndTime=23:30:00
HeartBtInt=20
SocketConnectPort=9823
SocketConnectHost=123.123.123.123
DataDictionary=somewhere/FIX41.xml


[SESSION]
BeginString=FIX.4.0
TargetCompID=ISLD
StartTime=12:00:00
EndTime=23:00:00
HeartBtInt=30
SocketConnectPort=8323
SocketConnectHost=23.23.23.23
DataDictionary=somewhere/FIX40.xml
        
[SESSION]
BeginString=FIX.4.2
SenderSubID=TWSub
SenderLocationID=TWLoc
TargetCompID=INCA
TargetSubID=INCASub
TargetLocationID=INCALoc
StartTime=12:30:00
EndTime=21:30:00
# overide default setting for RecconnectInterval
ReconnectInterval=30
HeartBtInt=30
SocketConnectPort=6523
SocketConnectHost=3.3.3.3
            
# (optional) alternate connection ports and hosts to cycle through on failover
SocketConnectPort1=8392
SocketConnectHost1=8.8.8.8
SocketConnectPort2=2932
SocketConnectHost2=12.12.12.12
DataDictionary=somewhere/FIX42.xml
"#
        .as_bytes();

        let s_result = Settings::parse(cfg).await;
        assert!(s_result.is_ok());

        let mut s = s_result.unwrap();

        struct GlobalTC<'a> {
            setting: &'a str,
            expected: &'a str,
        }

        let global_t_cs = vec![
            GlobalTC {
                setting: "ConnectionType",
                expected: "initiator",
            },
            GlobalTC {
                setting: "ReconnectInterval",
                expected: "60",
            },
            GlobalTC {
                setting: "SenderCompID",
                expected: "TW",
            },
        ];

        let global_settings = s.global_settings().await;
        for tc in global_t_cs.iter() {
            let actual_result = global_settings
                .read()
                .await
                .as_ref()
                .unwrap()
                .setting(tc.setting);
            assert!(actual_result.is_ok());
            assert_eq!(tc.expected, actual_result.unwrap());
        }

        let session_settings = s.session_settings().await;
        assert_eq!(session_settings.len(), 3);

        let session_id1 = SessionID {
            begin_string: "FIX.4.1".to_string(),
            sender_comp_id: "TW".to_string(),
            target_comp_id: "ARCA".to_string(),
            ..Default::default()
        };
        let session_id2 = SessionID {
            begin_string: "FIX.4.0".to_string(),
            sender_comp_id: "TW".to_string(),
            target_comp_id: "ISLD".to_string(),
            ..Default::default()
        };
        let session_id3 = SessionID {
            begin_string: "FIX.4.2".to_string(),
            sender_comp_id: "TW".to_string(),
            sender_sub_id: "TWSub".to_string(),
            sender_location_id: "TWLoc".to_string(),
            target_comp_id: "INCA".to_string(),
            target_sub_id: "INCASub".to_string(),
            target_location_id: "INCALoc".to_string(),
            ..Default::default()
        };

        struct SessionTC<'a> {
            session_id: Arc<SessionID>,
            setting: &'a str,
            expected: &'a str,
        }

        let arc_session_id1 = Arc::new(session_id1);
        let arc_session_id2 = Arc::new(session_id2);
        let arc_session_id3 = Arc::new(session_id3);

        let session_t_cs = vec![
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "ConnectionType",
                expected: "initiator",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "ReconnectInterval",
                expected: "60",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "SenderCompID",
                expected: "TW",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "BeginString",
                expected: "FIX.4.1",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "TargetCompID",
                expected: "ARCA",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "StartTime",
                expected: "12:30:00",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "EndTime",
                expected: "23:30:00",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "HeartBtInt",
                expected: "20",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "SocketConnectPort",
                expected: "9823",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "SocketConnectHost",
                expected: "123.123.123.123",
            },
            SessionTC {
                session_id: arc_session_id1.clone(),
                setting: "DataDictionary",
                expected: "somewhere/FIX41.xml",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "ConnectionType",
                expected: "initiator",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "ReconnectInterval",
                expected: "60",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "SenderCompID",
                expected: "TW",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "BeginString",
                expected: "FIX.4.0",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "TargetCompID",
                expected: "ISLD",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "StartTime",
                expected: "12:00:00",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "EndTime",
                expected: "23:00:00",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "HeartBtInt",
                expected: "30",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "SocketConnectPort",
                expected: "8323",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "SocketConnectHost",
                expected: "23.23.23.23",
            },
            SessionTC {
                session_id: arc_session_id2.clone(),
                setting: "DataDictionary",
                expected: "somewhere/FIX40.xml",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "ConnectionType",
                expected: "initiator",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "BeginString",
                expected: "FIX.4.2",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SenderCompID",
                expected: "TW",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "TargetCompID",
                expected: "INCA",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "StartTime",
                expected: "12:30:00",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "EndTime",
                expected: "21:30:00",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "ReconnectInterval",
                expected: "30",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "HeartBtInt",
                expected: "30",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectPort",
                expected: "6523",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectHost",
                expected: "3.3.3.3",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectPort1",
                expected: "8392",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectHost1",
                expected: "8.8.8.8",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectPort2",
                expected: "2932",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "SocketConnectHost2",
                expected: "12.12.12.12",
            },
            SessionTC {
                session_id: arc_session_id3.clone(),
                setting: "DataDictionary",
                expected: "somewhere/FIX42.xml",
            },
        ];

        for tc in session_t_cs.iter() {
            let settings_result = session_settings.get(&tc.session_id);
            assert!(
                settings_result.is_some(),
                "No Session recalled for {:?}",
                &tc.session_id
            );
            let settings = settings_result.unwrap();
            let actual_result = settings.setting(tc.setting);
            assert!(actual_result.is_ok());
            assert_eq!(tc.expected, actual_result.unwrap());
        }
    }

    #[tokio::test]
    async fn test_settings_parse_settings_with_equals_sign_in_value() {
        let reader = r#"[DEFAULT]
ConnectionType=initiator
SQLDriver=mysql
SQLDataSourceName=root:root@/quickfix?parseTime=true&loc=UTC
[SESSION]

BeginString=FIX.4.2
SenderCompID=SENDER
TargetCompID=TARGET
"#
        .as_bytes();

        let s_result = Settings::parse(reader).await;
        assert!(s_result.is_ok());

        let s = s_result.unwrap();
        let session_settings = s.session_settings().await;
        let session_settings_result = session_settings.get(&Arc::new(SessionID {
            begin_string: String::from("FIX.4.2"),
            sender_comp_id: String::from("SENDER"),
            target_comp_id: String::from("TARGET"),
            ..Default::default()
        }));
        assert!(session_settings_result.is_some());

        let inner_session_settings = session_settings_result.unwrap();

        let val_result = inner_session_settings.setting("SQLDataSourceName");
        assert!(val_result.is_ok());
        assert_eq!(
            "root:root@/quickfix?parseTime=true&loc=UTC",
            val_result.unwrap()
        )
    }

    #[tokio::test]
    async fn test_settings_session_id_from_session_settings() {
        #[derive(Default)]
        struct TestCase<'a> {
            global_begin_string: &'a str,
            global_target_comp_id: &'a str,
            global_sender_comp_id: &'a str,
            session_begin_string: &'a str,
            session_target_comp_id: &'a str,
            session_sender_comp_id: &'a str,
            session_qualifier: &'a str,
            expected_session_id: SessionID,
        }
        let test_cases = vec![
            TestCase {
                global_begin_string: "FIX.4.0",
                global_target_comp_id: "CB",
                global_sender_comp_id: "SS",
                expected_session_id: SessionID {
                    begin_string: "FIX.4.0".to_string(),
                    target_comp_id: "CB".to_string(),
                    sender_comp_id: "SS".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            TestCase {
                session_begin_string: "FIX.4.1",
                session_target_comp_id: "GE",
                session_sender_comp_id: "LE",
                expected_session_id: SessionID {
                    begin_string: "FIX.4.1".to_string(),
                    target_comp_id: "GE".to_string(),
                    sender_comp_id: "LE".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            TestCase {
                global_begin_string: "FIX.4.2",
                global_target_comp_id: "CB",
                session_target_comp_id: "GE",
                session_sender_comp_id: "LE",
                session_qualifier: "J",
                expected_session_id: SessionID {
                    begin_string: "FIX.4.2".to_string(),
                    target_comp_id: "GE".to_string(),
                    sender_comp_id: "LE".to_string(),
                    qualifier: "J".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        ];

        for tc in test_cases.iter() {
            let mut global_settings = SessionSettings::new();
            let mut session_settings = SessionSettings::new();

            if tc.global_begin_string != "" {
                global_settings.set(BEGIN_STRING.to_string(), tc.global_begin_string.to_string());
            }

            if tc.session_begin_string != "" {
                session_settings.set(
                    BEGIN_STRING.to_string(),
                    tc.session_begin_string.to_string(),
                );
            }

            if tc.global_target_comp_id != "" {
                global_settings.set(
                    TARGET_COMP_ID.to_string(),
                    tc.global_target_comp_id.to_string(),
                );
            }

            if tc.session_target_comp_id != "" {
                session_settings.set(
                    TARGET_COMP_ID.to_string(),
                    tc.session_target_comp_id.to_string(),
                );
            }

            if tc.global_sender_comp_id != "" {
                global_settings.set(
                    SENDER_COMP_ID.to_string(),
                    tc.global_sender_comp_id.to_string(),
                );
            }

            if tc.session_sender_comp_id != "" {
                session_settings.set(
                    SENDER_COMP_ID.to_string(),
                    tc.session_sender_comp_id.to_string(),
                );
            }

            if tc.session_qualifier.len() > 0 {
                session_settings.set(
                    SESSION_QUALIFIER.to_string(),
                    tc.session_qualifier.to_string(),
                );
            }

            let actual_session_id =
                session_id_from_session_settings(&global_settings, &session_settings);

            assert_eq!(
                &tc.expected_session_id, &*actual_session_id,
                "Expected {:?}, got {:?}",
                &tc.expected_session_id, &*actual_session_id
            );
        }
    }
}
