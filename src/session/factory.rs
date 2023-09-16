use crate::{
    application::Application,
    config::{
        APP_DATA_DICTIONARY, CHECK_LATENCY, DATA_DICTIONARY, DEFAULT_APPL_VER_ID,
        ENABLE_LAST_MSG_SEQ_NUM_PROCESSED, END_DAY, END_TIME, HEART_BT_INT, HEART_BT_INT_OVERRIDE,
        LOGON_TIMEOUT, LOGOUT_TIMEOUT, MAX_LATENCY, PERSIST_MESSAGES, RECONNECT_INTERVAL,
        REFRESH_ON_LOGON, REJECT_INVALID_MESSAGE, RESEND_REQUEST_CHUNK_SIZE, RESET_ON_DISCONNECT,
        RESET_ON_LOGON, RESET_ON_LOGOUT, SOCKET_CONNECT_HOST, SOCKET_CONNECT_PORT, START_DAY,
        START_TIME, TIME_STAMP_PRECISION, TIME_ZONE, TRANSPORT_DATA_DICTIONARY,
        VALIDATE_FIELDS_OUT_OF_ORDER,
    },
    datadictionary::DataDictionary,
    errors::FixerError,
    fix_utc_timestamp::TimestampPrecision,
    internal::{
        event::Event,
        event_timer::EventTimer,
        session_settings::SessionSettings as InternalSessionSetting,
        time_range::{TimeOfDay, TimeRange},
    },
    log::{LogFactoryTrait, LogTrait},
    registry::register_session,
    session::{
        session_id::SessionID,
        session_state::{SessionStateEnum, StateMachine},
        settings::SessionSettings,
        Admin, AdminEnum, FixIn, MessageEvent, Session, SessionEvent,
    },
    store::MessageStoreFactoryTrait,
    validation::{ValidatorEnum, ValidatorSettings},
    BEGIN_STRING_FIX40, BEGIN_STRING_FIX41, BEGIN_STRING_FIX42, BEGIN_STRING_FIX43,
    BEGIN_STRING_FIX44,
};
use addr::parse_domain_name;
use chrono::{offset::Offset, Duration, FixedOffset, Local, TimeZone, Weekday};
use chrono_tz::Tz;
use once_cell::sync::Lazy;
use simple_error::{SimpleError, SimpleResult};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};
use tokio::sync::{
    mpsc::{channel, unbounded_channel},
    Mutex,
};

static DAY_LOOKUP: Lazy<HashMap<&str, Weekday>> = Lazy::new(|| {
    hashmap! {
        "Sunday"    => Weekday::Sun,
        "Monday"    => Weekday::Mon,
        "Tuesday"   => Weekday::Tue,
        "Wednesday" => Weekday::Wed,
        "Thursday"  => Weekday::Thu,
        "Friday"    => Weekday::Fri,
        "Saturday"  => Weekday::Sat,

        "Sun"       => Weekday::Sun,
        "Mon"       => Weekday::Mon,
        "Tue"       => Weekday::Tue,
        "Wed"       => Weekday::Wed,
        "Thu"       => Weekday::Thu,
        "Fri"       => Weekday::Fri,
        "Sat"       => Weekday::Sat,
    }
});

static APPL_VER_ID_LOOKUP: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    hashmap! {
        BEGIN_STRING_FIX40 => "2",
        BEGIN_STRING_FIX41 => "3",
        BEGIN_STRING_FIX42 => "4",
        BEGIN_STRING_FIX43 => "5",
        BEGIN_STRING_FIX44 => "6",
        "FIX.5.0"          => "7",
        "FIX.5.0SP1"       => "8",
        "FIX.5.0SP2"       => "9",
    }
});

#[derive(Default)]
pub struct SessionFactory {
    // true if building sessions that initiate logon.
    pub build_initiators: bool,
}

impl SessionFactory {
    // creates Session, associates with internal session registry.
    pub async fn create_session<
        F: MessageStoreFactoryTrait,
        A: Application + 'static,
        L: LogFactoryTrait,
    >(
        &self,
        session_id: Arc<SessionID>,
        store_factory: F,
        settings: &SessionSettings,
        log_factory: L,
        application: Arc<Mutex<A>>,
    ) -> SimpleResult<Arc<Mutex<Session>>> {
        let session = self
            .new_session(
                session_id,
                store_factory,
                settings,
                log_factory,
                application.clone(),
            )
            .await?;

        let session_id = session.session_id.clone();
        let arc_session = Arc::new(Mutex::new(session));

        register_session(arc_session.clone()).await?;

        let mut application_lock = application.lock().await;
        application_lock.on_create(session_id);

        arc_session
            .lock()
            .await
            .log
            .on_event("Created session")
            .await;

        Ok(arc_session)
    }

    async fn new_session<
        F: MessageStoreFactoryTrait,
        A: Application + 'static,
        L: LogFactoryTrait,
    >(
        &self,
        session_id: Arc<SessionID>,
        store_factory: F,
        settings: &SessionSettings,
        mut log_factory: L,
        application: Arc<Mutex<A>>,
    ) -> SimpleResult<Session> {
        let mut iss = InternalSessionSetting::default();

        let mut validator_settings = ValidatorSettings::default();
        if settings.has_setting(VALIDATE_FIELDS_OUT_OF_ORDER) {
            let check_fields_out_of_order = settings.bool_setting(VALIDATE_FIELDS_OUT_OF_ORDER)?;
            validator_settings.check_fields_out_of_order = check_fields_out_of_order;
        }

        if settings.has_setting(REJECT_INVALID_MESSAGE) {
            let reject_invalid_message = settings.bool_setting(REJECT_INVALID_MESSAGE)?;
            validator_settings.reject_invalid_message = reject_invalid_message;
        }

        let mut default_appl_ver_id = Default::default();
        let mut transport_data_dictionary: Option<DataDictionary> = None;
        let mut app_data_dictionary: Option<DataDictionary> = None;

        let validator = if session_id.is_fixt() {
            default_appl_ver_id = settings.setting(DEFAULT_APPL_VER_ID)?;
            iss.default_appl_ver_id = default_appl_ver_id.clone();

            if let Some(appl_ver_id) = APPL_VER_ID_LOOKUP.get(default_appl_ver_id.as_str()) {
                iss.default_appl_ver_id = appl_ver_id.to_string();
            }

            // If the transport or app data dictionary setting is set, the other also needs to be set.
            if settings.has_setting(TRANSPORT_DATA_DICTIONARY)
                || settings.has_setting(APP_DATA_DICTIONARY)
            {
                let transport_data_dictionary_path = settings.setting(TRANSPORT_DATA_DICTIONARY)?;
                let app_data_dictionary_path = settings.setting(APP_DATA_DICTIONARY)?;

                let transport_data_dictionary_inner = map_err_with!(
                    DataDictionary::parse(&transport_data_dictionary_path).await,
                    "problem parsing XML datadictionary path '{}' for setting '{}'",
                    settings
                        .settings
                        .get(TRANSPORT_DATA_DICTIONARY)
                        .as_ref()
                        .unwrap()
                        .deref(),
                    TRANSPORT_DATA_DICTIONARY
                )?;

                let app_data_dictionary_inner = map_err_with!(
                    DataDictionary::parse(&app_data_dictionary_path).await,
                    "problem parsing XML datadictionary path '{}' for setting '{}'",
                    settings
                        .settings
                        .get(APP_DATA_DICTIONARY)
                        .as_ref()
                        .unwrap()
                        .deref(),
                    APP_DATA_DICTIONARY
                )?;

                transport_data_dictionary = Some(transport_data_dictionary_inner);
                app_data_dictionary = Some(app_data_dictionary_inner.clone());

                Some(ValidatorEnum::new(
                    validator_settings,
                    app_data_dictionary_inner.clone(),
                    transport_data_dictionary.clone(),
                ))
            } else {
                None
            }
        } else {
            if settings.has_setting(DATA_DICTIONARY) {
                let data_dictionary_path = settings.setting(DATA_DICTIONARY)?;

                let app_data_dictionary_inner = map_err_with!(
                    DataDictionary::parse(&data_dictionary_path).await,
                    "problem parsing XML datadictionary path '{}' for setting '{}'",
                    settings
                        .settings
                        .get(DATA_DICTIONARY)
                        .as_ref()
                        .unwrap()
                        .deref(),
                    DATA_DICTIONARY
                )?;

                app_data_dictionary = Some(app_data_dictionary_inner.clone());

                Some(ValidatorEnum::new(
                    validator_settings,
                    app_data_dictionary_inner.clone(),
                    None,
                ))
            } else {
                None
            }
        };

        if settings.has_setting(RESET_ON_LOGON) {
            let st = settings.bool_setting(RESET_ON_LOGON)?;
            iss.reset_on_logon = st;
        }

        if settings.has_setting(REFRESH_ON_LOGON) {
            let st = settings.bool_setting(REFRESH_ON_LOGON)?;
            iss.refresh_on_logon = st;
        }

        if settings.has_setting(RESET_ON_LOGOUT) {
            let st = settings.bool_setting(RESET_ON_LOGOUT)?;
            iss.reset_on_logout = st;
        }

        if settings.has_setting(RESET_ON_DISCONNECT) {
            let st = settings.bool_setting(RESET_ON_DISCONNECT)?;
            iss.reset_on_disconnect = st;
        }

        if settings.has_setting(ENABLE_LAST_MSG_SEQ_NUM_PROCESSED) {
            let st = settings.bool_setting(ENABLE_LAST_MSG_SEQ_NUM_PROCESSED)?;
            iss.enable_last_msg_seq_num_processed = st;
        }

        if settings.has_setting(CHECK_LATENCY) {
            let st = settings.bool_setting(CHECK_LATENCY)?;
            iss.skip_check_latency = !st;
        }

        if settings.has_setting(MAX_LATENCY) {
            let st = settings.int_setting(MAX_LATENCY)?;
            if st <= 0 {
                return Err(simple_error!("MaxLatency must be a positive integer"));
            }
            iss.max_latency = Duration::seconds(st as i64);
        } else {
            iss.max_latency = Duration::seconds(120);
        }

        if settings.has_setting(RESEND_REQUEST_CHUNK_SIZE) {
            let st = settings.int_setting(RESEND_REQUEST_CHUNK_SIZE)?;
            iss.resend_request_chunk_size = st;
        }

        if settings.has_setting(START_TIME) || settings.has_setting(END_TIME) {
            let start_time_string = settings.setting(START_TIME)?;
            let end_time_string = settings.setting(END_TIME)?;

            let start_time = map_err_with!(
                TimeOfDay::parse(&start_time_string),
                "problem parsing time of day '{}' for setting '{}'",
                settings.settings.get(START_TIME).as_ref().unwrap().deref(),
                START_TIME
            )?;
            let end_time = map_err_with!(
                TimeOfDay::parse(&end_time_string),
                "problem parsing time of day '{}' for setting '{}'",
                settings.settings.get(END_TIME).as_ref().unwrap().deref(),
                END_TIME
            )?;

            let mut loc = FixedOffset::west_opt(0).unwrap();

            if settings.has_setting(TIME_ZONE) {
                let loc_str = map_err_with!(
                    settings.setting(TIME_ZONE),
                    "problem parsing time zone '{}' for setting '{}'",
                    settings.settings.get(TIME_ZONE).as_ref().unwrap().deref(),
                    TIME_ZONE
                )?;

                if loc_str != "Local" {
                    let tz: Tz = map_err_with!(
                        (&loc_str).parse().map_err(|err| simple_error!("{}", err)),
                        "problem parsing time zone '{}' for setting '{}'",
                        settings.settings.get(TIME_ZONE).as_ref().unwrap().deref(),
                        TIME_ZONE
                    )?;

                    loc = tz
                        .with_ymd_and_hms(2020, 10, 10, 10, 10, 10)
                        .unwrap()
                        .offset()
                        .fix();
                } else {
                    loc = Local
                        .with_ymd_and_hms(2020, 10, 10, 10, 10, 10)
                        .unwrap()
                        .offset()
                        .fix();
                }
            }

            if !settings.has_setting(START_DAY) && !settings.has_setting(END_DAY) {
                iss.session_time = Some(TimeRange::new_in_location(start_time, end_time, loc));
            } else {
                let start_day_string = settings.setting(START_DAY)?;
                let end_day_string = settings.setting(END_DAY)?;

                fn parse_day(setting: &str, day_str: &str) -> SimpleResult<Weekday> {
                    let day_result = DAY_LOOKUP.get(day_str);
                    match day_result {
                        Some(day) => Ok(*day),
                        None => Err(FixerError::new_incorrect_format_for_setting(
                            setting, day_str,
                        ))
                        .map_err(SimpleError::from),
                    }
                }

                let start_day = parse_day(START_DAY, &start_day_string)?;
                let end_day = parse_day(END_DAY, &end_day_string)?;

                iss.session_time = Some(TimeRange::new_week_range_in_location(
                    start_time, end_time, start_day, end_day, loc,
                ))
            }
        }

        let mut precision = TimestampPrecision::default();

        if settings.has_setting(TIME_STAMP_PRECISION) {
            let precision_str = settings.setting(TIME_STAMP_PRECISION)?;

            if precision_str.as_str() == "SECONDS" {
                precision = TimestampPrecision::Seconds;
            } else if precision_str == "MILLIS" {
                precision = TimestampPrecision::Millis;
            } else if precision_str == "MICROS" {
                precision = TimestampPrecision::Micros;
            } else if precision_str == "NANOS" {
                precision = TimestampPrecision::Nanos;
            } else {
                return Err(FixerError::new_incorrect_format_for_setting(
                    TIME_STAMP_PRECISION,
                    precision_str.as_str(),
                ))
                .map_err(SimpleError::from);
            }
        }

        if settings.has_setting(PERSIST_MESSAGES) {
            let st = settings.bool_setting(PERSIST_MESSAGES)?;
            iss.disable_message_persist = !st;
        }

        if self.build_initiators {
            self.build_initiator_settings(&mut iss, settings).await?;
        } else {
            self.build_acceptor_settings(&mut iss, settings).await?;
        }

        let log = log_factory
            .create_session_log(session_id.clone())
            .await
            .map_err(|err| simple_error!("{}", err))?;

        let store = store_factory.create(session_id.clone()).await?;

        let (session_event_tx, session_event_rx) = unbounded_channel::<Event>();
        let (message_event_tx, message_event_rx) = channel::<bool>(1);
        let (admin_tx, admin_rx) = unbounded_channel::<AdminEnum>();
        let (message_out_tx, _) = unbounded_channel::<Vec<u8>>();
        let (_, message_in_rx) = unbounded_channel::<FixIn>();

        Ok(Session {
            application: application.clone(),
            session_id,
            store,
            log,
            message_out: message_out_tx,
            message_in: message_in_rx,
            to_send: Default::default(),
            session_event: SessionEvent {
                tx: session_event_tx,
                rx: session_event_rx,
            },
            message_event: MessageEvent {
                tx: message_event_tx,
                rx: message_event_rx,
            },
            validator,
            sm: StateMachine {
                state: SessionStateEnum::new_latent_state(),
                pending_stop: false,
                stopped: false,
                notify_on_in_session_time: None,
            },
            state_timer: EventTimer::new(Arc::new(|| {})),
            peer_timer: EventTimer::new(Arc::new(|| {})),
            sent_reset: Default::default(),
            stop_once: Default::default(),
            target_default_appl_ver_id: default_appl_ver_id,
            admin: Admin {
                tx: admin_tx,
                rx: admin_rx,
            },
            iss,
            transport_data_dictionary,
            app_data_dictionary,
            timestamp_precision: precision,
        })
    }

    async fn build_acceptor_settings(
        &self,
        iss: &mut InternalSessionSetting,
        settings: &SessionSettings,
    ) -> SimpleResult<()> {
        self.build_heart_bt_int_settings(iss, settings, false).await
    }

    async fn build_initiator_settings(
        &self,
        iss: &mut InternalSessionSetting,
        settings: &SessionSettings,
    ) -> SimpleResult<()> {
        iss.initiate_logon = true;

        self.build_heart_bt_int_settings(iss, settings, true)
            .await?;

        iss.reconnect_interval = Duration::seconds(30);
        if settings.has_setting(RECONNECT_INTERVAL) {
            let interval = settings.int_setting(RECONNECT_INTERVAL)?;

            if interval <= 0 {
                return Err(simple_error!("ReconnectInterval must be greater than zero"));
            }

            iss.reconnect_interval = Duration::seconds(interval as i64);
        }

        iss.logout_timeout = Duration::seconds(2);
        if settings.has_setting(LOGOUT_TIMEOUT) {
            let timeout = settings.int_setting(LOGOUT_TIMEOUT)?;

            if timeout <= 0 {
                return Err(simple_error!("LogoutTimeout must be greater than zero"));
            }

            iss.logout_timeout = Duration::seconds(timeout as i64);
        }

        iss.logon_timeout = Duration::seconds(10);
        if settings.has_setting(LOGON_TIMEOUT) {
            let timeout = settings.int_setting(LOGON_TIMEOUT)?;

            if timeout <= 0 {
                return Err(simple_error!("LogonTimeout must be greater than zero"));
            }

            iss.logon_timeout = Duration::seconds(timeout as i64);
        }

        self.configure_socket_connect_address(iss, settings).await
    }

    async fn configure_socket_connect_address(
        &self,
        iss: &mut InternalSessionSetting,
        settings: &SessionSettings,
    ) -> SimpleResult<()> {
        iss.socket_connect_address = vec![];

        let mut i = 0;

        loop {
            let mut host_config = SOCKET_CONNECT_HOST.to_string();
            let mut port_config = SOCKET_CONNECT_PORT.to_string();
            if i > 0 {
                host_config = format!("{}{}", SOCKET_CONNECT_HOST, i);
                port_config = format!("{}{}", SOCKET_CONNECT_PORT, i);
                if !(settings.has_setting(&host_config) || settings.has_setting(&port_config)) {
                    break;
                }
            }

            let socket_connect_host_string = settings.setting(&host_config)?;
            let socket_connect_port_string = settings.setting(&port_config)?;

            let socket_connect_port =
                atoi_simd::parse::<u16>(&socket_connect_port_string.as_bytes())
                    .map_err(SimpleError::from)?;

            let host_ip = IpAddr::from_str(socket_connect_host_string.as_str());

            let socket_connect_address_result: Result<String, SimpleError> = match host_ip {
                Ok(ip_addr) => {
                    let socket = match ip_addr {
                        IpAddr::V4(ip) => {
                            SocketAddr::V4(SocketAddrV4::new(ip, socket_connect_port))
                        }
                        IpAddr::V6(ip) => {
                            SocketAddr::V6(SocketAddrV6::new(ip, socket_connect_port, 0, 0))
                        }
                    };
                    Ok(format!("{}", socket))
                }
                Err(_) => match parse_domain_name(socket_connect_host_string.as_str()) {
                    Ok(name) => Ok(format!("{}:{}", name.as_str(), socket_connect_port)),
                    Err(err) => Err(SimpleError::from(err)),
                },
            };
            if let Err(err) = socket_connect_address_result {
                return Err(err);
            }

            iss.socket_connect_address
                .push(socket_connect_address_result.unwrap());

            i += 1;
        }

        Ok(())
    }

    async fn build_heart_bt_int_settings(
        &self,
        iss: &mut InternalSessionSetting,
        settings: &SessionSettings,
        must_provide: bool,
    ) -> SimpleResult<()> {
        if settings.has_setting(HEART_BT_INT_OVERRIDE) {
            let st = settings.bool_setting(HEART_BT_INT_OVERRIDE)?;
            iss.heart_bt_int_override = st;
        }

        if iss.heart_bt_int_override || must_provide {
            let heart_bt_int = settings.int_setting(HEART_BT_INT)?;
            if heart_bt_int <= 0 {
                return Err(simple_error!("Heartbeat must be greater than zero"));
            }
            iss.heart_bt_int = Duration::seconds(heart_bt_int as i64);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{
            CHECK_LATENCY, DEFAULT_APPL_VER_ID, ENABLE_LAST_MSG_SEQ_NUM_PROCESSED, END_DAY,
            END_TIME, HEART_BT_INT, HEART_BT_INT_OVERRIDE, LOGON_TIMEOUT, LOGOUT_TIMEOUT,
            MAX_LATENCY, PERSIST_MESSAGES, RECONNECT_INTERVAL, REFRESH_ON_LOGON,
            RESEND_REQUEST_CHUNK_SIZE, RESET_ON_DISCONNECT, RESET_ON_LOGON, RESET_ON_LOGOUT,
            SOCKET_CONNECT_HOST, SOCKET_CONNECT_PORT, START_DAY, START_TIME, TIME_STAMP_PRECISION,
            TIME_ZONE,
        },
        fix_utc_timestamp::TimestampPrecision,
        fixer_test::MockApp,
        internal::time_range::{TimeOfDay, TimeRange},
        log::LogFactoryEnum,
        session::{
            factory::SessionFactory, session_id::SessionID, settings::SessionSettings, Session,
        },
        store::{MemoryStoreFactory, MessageStoreFactoryEnum},
        BEGIN_STRING_FIXT11,
    };
    use chrono::{Duration, Local, TimeZone, Weekday};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct SessionFactorySuite {
        factory: SessionFactory,
        session_id: Arc<SessionID>,
        store_factory: MessageStoreFactoryEnum,
        ss: SessionSettings,
        log_factory: LogFactoryEnum,
        app: Arc<Mutex<MockApp>>,
    }

    impl SessionFactorySuite {
        fn setup_test() -> SessionFactorySuite {
            let factory = SessionFactory::default();
            let session_id = Arc::new(SessionID {
                begin_string: "FIX.4.2".to_string(),
                target_comp_id: "TW".to_string(),
                sender_comp_id: "ISLD".to_string(),
                ..Default::default()
            });
            let store_factory = MemoryStoreFactory::new();
            let ss = SessionSettings::default();
            let log_factory = LogFactoryEnum::default();
            let app = Arc::new(Mutex::new(MockApp::default()));
            SessionFactorySuite {
                factory,
                session_id,
                store_factory,
                ss,
                log_factory,
                app,
            }
        }
    }

    #[tokio::test]
    async fn test_defaults() {
        let s = SessionFactorySuite::setup_test();
        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();

        assert!(!session.iss.reset_on_logon);
        assert!(!session.iss.refresh_on_logon);
        assert!(!session.iss.reset_on_logout);
        assert!(!session.iss.reset_on_disconnect);
        assert!(
            session.iss.session_time.is_none(),
            "By default, start and end time unset"
        );
        assert_eq!("", &session.iss.default_appl_ver_id);

        assert!(!session.iss.initiate_logon);
        assert_eq!(0, session.iss.resend_request_chunk_size);
        assert!(!session.iss.enable_last_msg_seq_num_processed);
        assert!(!session.iss.skip_check_latency);
        assert_eq!(TimestampPrecision::Millis, session.timestamp_precision);
        assert_eq!(Duration::seconds(120), session.iss.max_latency);
        assert!(!session.iss.disable_message_persist);
        assert!(!session.iss.heart_bt_int_override);
    }

    #[tokio::test]
    async fn test_reset_on_logon() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: true,
            },
            TestCase {
                setting: "N",
                expected: false,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(RESET_ON_LOGON.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.reset_on_logon);
        }
    }

    #[tokio::test]
    async fn test_refresh_on_logon() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: true,
            },
            TestCase {
                setting: "N",
                expected: false,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(REFRESH_ON_LOGON.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.refresh_on_logon);
        }
    }

    #[tokio::test]
    async fn test_reset_on_logout() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: true,
            },
            TestCase {
                setting: "N",
                expected: false,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(RESET_ON_LOGOUT.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.reset_on_logout);
        }
    }

    #[tokio::test]
    async fn test_reset_on_disconnect() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: true,
            },
            TestCase {
                setting: "N",
                expected: false,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(RESET_ON_DISCONNECT.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.reset_on_disconnect);
        }
    }

    #[tokio::test]
    async fn test_resend_request_chunk_size() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(RESEND_REQUEST_CHUNK_SIZE.to_string(), "2500".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(2500, session.iss.resend_request_chunk_size);
        s.ss.set(
            RESEND_REQUEST_CHUNK_SIZE.to_string(),
            "notanint".to_string(),
        );
        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_enable_last_msg_seq_num_processed() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: true,
            },
            TestCase {
                setting: "N",
                expected: false,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(
                ENABLE_LAST_MSG_SEQ_NUM_PROCESSED.to_string(),
                tc.setting.to_string(),
            );
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.enable_last_msg_seq_num_processed);
        }
    }

    #[tokio::test]
    async fn test_check_latency() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: false,
            },
            TestCase {
                setting: "N",
                expected: true,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(CHECK_LATENCY.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.skip_check_latency);
        }
    }

    #[tokio::test]
    async fn test_start_and_end_time() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert!(session.iss.session_time.is_some());
        assert_eq!(
            TimeRange::new_utc(TimeOfDay::new(12, 0, 0), TimeOfDay::new(14, 0, 0)),
            session.iss.session_time.unwrap()
        );
    }

    #[tokio::test]
    async fn test_start_and_end_time_and_time_zone() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(TIME_ZONE.to_string(), "Local".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        let loc = Local.with_ymd_and_hms(2020, 10, 10, 10, 10, 10).unwrap();
        let offset = loc.offset();

        assert_eq!(
            TimeRange::new_in_location(TimeOfDay::new(12, 0, 0), TimeOfDay::new(14, 0, 0), *offset),
            session.iss.session_time.unwrap()
        );
    }

    #[tokio::test]
    async fn test_start_and_end_time_and_start_and_end_day() {
        struct TestCase<'a> {
            start_day: &'a str,
            end_day: &'a str,
        }
        let tests = vec![
            TestCase {
                start_day: "Sunday",
                end_day: "Thursday",
            },
            TestCase {
                start_day: "Sun",
                end_day: "Thu",
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
            s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
            s.ss.set(START_DAY.to_string(), tc.start_day.to_string());
            s.ss.set(END_DAY.to_string(), tc.end_day.to_string());

            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();

            assert_eq!(
                TimeRange::new_utc_week_range(
                    TimeOfDay::new(12, 0, 0),
                    TimeOfDay::new(14, 0, 0),
                    Weekday::Sun,
                    Weekday::Thu
                ),
                session.iss.session_time.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_start_and_end_time_and_start_and_end_day_and_time_zone() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(START_DAY.to_string(), "Sunday".to_string());
        s.ss.set(END_DAY.to_string(), "Thursday".to_string());
        s.ss.set(TIME_ZONE.to_string(), "Local".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();

        let loc = Local.with_ymd_and_hms(2020, 10, 10, 10, 10, 10).unwrap();
        let offset = loc.offset();

        assert_eq!(
            TimeRange::new_week_range_in_location(
                TimeOfDay::new(12, 0, 0),
                TimeOfDay::new(14, 0, 0),
                Weekday::Sun,
                Weekday::Thu,
                *offset,
            ),
            session.iss.session_time.unwrap()
        );
    }

    #[tokio::test]
    async fn test_missing_start_or_end_time() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());

        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_start_or_end_time_parse_error() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "1200:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());

        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_time_zone() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "1200:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(TIME_ZONE.to_string(), "not valid".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_missing_start_or_end_day() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(START_DAY.to_string(), "Thursday".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());

        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(END_DAY.to_string(), "Sunday".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_start_or_end_day_parse_error() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(START_DAY.to_string(), "notvalid".to_string());
        s.ss.set(END_DAY.to_string(), "Sunday".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());

        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(START_TIME.to_string(), "12:00:00".to_string());
        s.ss.set(END_TIME.to_string(), "14:00:00".to_string());
        s.ss.set(START_DAY.to_string(), "Sunday".to_string());
        s.ss.set(END_DAY.to_string(), "blah".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id,
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());
    }

    #[tokio::test]
    async fn test_default_appl_ver_id() {
        let mut s = SessionFactorySuite::setup_test();

        let session_id = Arc::new(SessionID {
            begin_string: BEGIN_STRING_FIXT11.to_string(),
            target_comp_id: "TW".to_string(),
            sender_comp_id: "ISLD".to_string(),
            ..Default::default()
        });

        s.session_id = session_id;

        struct TestCase<'a> {
            expected: &'a str,
            config: &'a str,
        }
        let tests = vec![
            TestCase {
                expected: "2",
                config: "2",
            },
            TestCase {
                expected: "2",
                config: "FIX.4.0",
            },
            TestCase {
                expected: "3",
                config: "3",
            },
            TestCase {
                expected: "3",
                config: "FIX.4.1",
            },
            TestCase {
                expected: "4",
                config: "4",
            },
            TestCase {
                expected: "4",
                config: "FIX.4.2",
            },
            TestCase {
                expected: "5",
                config: "5",
            },
            TestCase {
                expected: "5",
                config: "FIX.4.3",
            },
            TestCase {
                expected: "6",
                config: "6",
            },
            TestCase {
                expected: "6",
                config: "FIX.4.4",
            },
            TestCase {
                expected: "7",
                config: "7",
            },
            TestCase {
                expected: "7",
                config: "FIX.5.0",
            },
            TestCase {
                expected: "8",
                config: "8",
            },
            TestCase {
                expected: "8",
                config: "FIX.5.0SP1",
            },
            TestCase {
                expected: "9",
                config: "9",
            },
            TestCase {
                expected: "9",
                config: "FIX.5.0SP2",
            },
        ];

        for tc in tests.iter() {
            s.ss.set(DEFAULT_APPL_VER_ID.to_string(), tc.config.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id.clone(),
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, &session.iss.default_appl_ver_id);
        }
    }

    #[tokio::test]
    async fn test_new_session_build_initiators() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = true;
        s.ss.set(HEART_BT_INT.to_string(), "34".to_string());
        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "5000".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert!(session.iss.initiate_logon);

        assert_eq!(Duration::seconds(34), session.iss.heart_bt_int);
        assert_eq!(Duration::seconds(30), session.iss.reconnect_interval);
        assert_eq!(Duration::seconds(10), session.iss.logon_timeout);
        assert_eq!(Duration::seconds(2), session.iss.logout_timeout);
        assert_eq!("127.0.0.1:5000", session.iss.socket_connect_address[0]);
    }

    #[tokio::test]
    async fn test_new_session_build_acceptors() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = false;
        s.ss.set(HEART_BT_INT.to_string(), "34".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();

        assert!(!session.iss.initiate_logon);
        assert_eq!(session.iss.heart_bt_int, Duration::seconds(0));
        assert!(!session.iss.heart_bt_int_override);

        s.ss.set(HEART_BT_INT_OVERRIDE.to_string(), "Y".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();

        assert!(!session.iss.initiate_logon);
        assert_eq!(session.iss.heart_bt_int, Duration::seconds(34));
        assert!(session.iss.heart_bt_int_override);
    }

    #[tokio::test]
    async fn test_new_session_build_initiators_valid_heart_bt_int() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = true;

        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int should be required for acceptors with override defined"
        );

        s.ss.set(HEART_BT_INT.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "heart_bt_int must be a number");

        s.ss.set(HEART_BT_INT.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int must be greater than zero"
        );

        s.ss.set(HEART_BT_INT.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int must be greater than zero"
        );
    }

    #[tokio::test]
    async fn test_new_session_build_acceptors_valid_heart_bt_int() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = false;

        s.ss.set(HEART_BT_INT_OVERRIDE.to_string(), "Y".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int should be required for initiators"
        );

        s.ss.set(HEART_BT_INT.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "heart_bt_int must be a number");

        s.ss.set(HEART_BT_INT.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int must be greater than zero"
        );

        s.ss.set(HEART_BT_INT.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "heart_bt_int must be greater than zero"
        );
    }

    #[tokio::test]
    async fn test_new_session_build_initiators_valid_reconnect_interval() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = true;
        s.ss.set(HEART_BT_INT.to_string(), "34".to_string());
        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "3000".to_string());

        s.ss.set(RECONNECT_INTERVAL.to_string(), "45".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(Duration::seconds(45), session.iss.reconnect_interval);

        s.ss.set(RECONNECT_INTERVAL.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "reconnect_interval must be a number"
        );

        s.ss.set(RECONNECT_INTERVAL.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "reconnect_interval must be greater than zero"
        );

        s.ss.set(RECONNECT_INTERVAL.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "reconnect_interval must be greater than zero"
        );
    }

    #[tokio::test]
    async fn test_new_session_build_initiators_valid_logout_timeout() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = true;
        s.ss.set(HEART_BT_INT.to_string(), "34".to_string());
        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "3000".to_string());

        s.ss.set(LOGOUT_TIMEOUT.to_string(), "45".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(Duration::seconds(45), session.iss.logout_timeout);

        s.ss.set(LOGOUT_TIMEOUT.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "logout_timeout must be a number");

        s.ss.set(LOGOUT_TIMEOUT.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "logout_timeout must be greater than zero"
        );

        s.ss.set(LOGOUT_TIMEOUT.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "logout_timeout must be greater than zero"
        );
    }

    #[tokio::test]
    async fn test_new_session_build_initiators_valid_logon_timeout() {
        let mut s = SessionFactorySuite::setup_test();
        s.factory.build_initiators = true;
        s.ss.set(HEART_BT_INT.to_string(), "34".to_string());
        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "3000".to_string());

        s.ss.set(LOGON_TIMEOUT.to_string(), "45".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(Duration::seconds(45), session.iss.logon_timeout);

        s.ss.set(LOGON_TIMEOUT.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "logon_timeout must be a number");

        s.ss.set(LOGON_TIMEOUT.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "logon_timeout must be greater than zero"
        );

        s.ss.set(LOGON_TIMEOUT.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(
            session_result.is_err(),
            "logon_timeout must be greater than zero"
        );
    }

    #[tokio::test]
    async fn test_configure_socket_connect_address() {
        let mut s = SessionFactorySuite::setup_test();
        let mut sess = Session::default();
        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut sess.iss, &s.ss)
            .await;
        assert!(
            configure_result.is_err(),
            "SocketConnectHost and SocketConnectPort should be required"
        );

        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut sess.iss, &s.ss)
            .await;
        assert!(
            configure_result.is_err(),
            "SocketConnectHost and SocketConnectPort should be required"
        );

        s.ss = SessionSettings::new();
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "5000".to_string());
        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut sess.iss, &s.ss)
            .await;
        assert!(
            configure_result.is_err(),
            "SocketConnectHost and SocketConnectPort should be required"
        );

        struct TestCase<'a> {
            host: &'a str,
            port: &'a str,
            expected: &'a str,
        }
        let tests = vec![
            TestCase {
                host: "127.0.0.1",
                port: "3000",
                expected: "127.0.0.1:3000",
            },
            TestCase {
                host: "example.com",
                port: "5000",
                expected: "example.com:5000",
            },
            TestCase {
                host: "2001:db8:a0b:12f0::1",
                port: "3001",
                expected: "[2001:db8:a0b:12f0::1]:3001",
            },
        ];

        for tc in tests.iter() {
            let mut sess = Session::default();
            s.ss.set(SOCKET_CONNECT_HOST.to_string(), tc.host.to_string());
            s.ss.set(SOCKET_CONNECT_PORT.to_string(), tc.port.to_string());
            let configure_result = s
                .factory
                .configure_socket_connect_address(&mut sess.iss, &s.ss)
                .await;
            assert!(configure_result.is_ok());
            assert_eq!(sess.iss.socket_connect_address.len(), 1);
            assert_eq!(tc.expected, &sess.iss.socket_connect_address[0]);
        }
    }

    #[tokio::test]
    async fn test_configure_socket_connect_address_multi() {
        let mut s = SessionFactorySuite::setup_test();
        let mut session = Session::default();

        s.ss.set(SOCKET_CONNECT_HOST.to_string(), "127.0.0.1".to_string());
        s.ss.set(SOCKET_CONNECT_PORT.to_string(), "3000".to_string());

        s.ss.set(
            format!("{}{}", SOCKET_CONNECT_HOST, 1),
            "127.0.0.2".to_string(),
        );
        s.ss.set(format!("{}{}", SOCKET_CONNECT_PORT, 1), "4000".to_string());

        s.ss.set(
            format!("{}{}", SOCKET_CONNECT_HOST, 2),
            "127.0.0.3".to_string(),
        );
        s.ss.set(format!("{}{}", SOCKET_CONNECT_PORT, 2), "5000".to_string());

        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut session.iss, &s.ss)
            .await;
        assert!(configure_result.is_ok());
        assert_eq!(session.iss.socket_connect_address.len(), 3);

        let tests = vec!["127.0.0.1:3000", "127.0.0.2:4000", "127.0.0.3:5000"];

        for (i, tc) in tests.iter().enumerate() {
            assert_eq!(tc, &session.iss.socket_connect_address[i]);
        }

        s.ss.set(
            format!("{}{}", SOCKET_CONNECT_HOST, 3),
            "127.0.0.4".to_string(),
        );

        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut session.iss, &s.ss)
            .await;
        assert!(
            configure_result.is_err(),
            "must have both host and port to be valid"
        );

        s.ss.set(format!("{}{}", SOCKET_CONNECT_PORT, 3), "5000".to_string());
        s.ss.set(format!("{}{}", SOCKET_CONNECT_PORT, 4), "5000".to_string());

        let configure_result = s
            .factory
            .configure_socket_connect_address(&mut session.iss, &s.ss)
            .await;
        assert!(
            configure_result.is_err(),
            "must have both host and port to be valid"
        );
    }

    #[tokio::test]
    async fn test_new_session_timestamp_precision() {
        let mut s = SessionFactorySuite::setup_test();
        s.ss.set(TIME_STAMP_PRECISION.to_string(), "blah".to_string());

        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err());

        struct TestCase<'a> {
            config: &'a str,
            precision: TimestampPrecision,
        }
        let tests = vec![
            TestCase {
                config: "SECONDS",
                precision: TimestampPrecision::Seconds,
            },
            TestCase {
                config: "MILLIS",
                precision: TimestampPrecision::Millis,
            },
            TestCase {
                config: "MICROS",
                precision: TimestampPrecision::Micros,
            },
            TestCase {
                config: "NANOS",
                precision: TimestampPrecision::Nanos,
            },
        ];

        for tc in tests.iter() {
            s.ss.set(TIME_STAMP_PRECISION.to_string(), tc.config.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id.clone(),
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(session.timestamp_precision, tc.precision);
        }
    }

    #[tokio::test]
    async fn test_new_session_max_latency() {
        let mut s = SessionFactorySuite::setup_test();

        s.ss.set(MAX_LATENCY.to_string(), "not a number".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "max_latency must be a number");

        s.ss.set(MAX_LATENCY.to_string(), "0".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "max_latency must be positive");

        s.ss.set(MAX_LATENCY.to_string(), "-20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_err(), "max_latency must be positive");

        s.ss.set(MAX_LATENCY.to_string(), "20".to_string());
        let session_result = s
            .factory
            .new_session(
                s.session_id.clone(),
                s.store_factory.clone(),
                &s.ss.clone(),
                s.log_factory.clone(),
                s.app.clone(),
            )
            .await;
        assert!(session_result.is_ok());
        let session = session_result.unwrap();
        assert_eq!(Duration::seconds(20), session.iss.max_latency);
    }

    #[tokio::test]
    async fn test_persist_messages() {
        struct TestCase<'a> {
            setting: &'a str,
            expected: bool,
        }
        let tests = vec![
            TestCase {
                setting: "Y",
                expected: false,
            },
            TestCase {
                setting: "N",
                expected: true,
            },
        ];

        for tc in tests.iter() {
            let mut s = SessionFactorySuite::setup_test();
            s.ss.set(PERSIST_MESSAGES.to_string(), tc.setting.to_string());
            let session_result = s
                .factory
                .new_session(
                    s.session_id,
                    s.store_factory.clone(),
                    &s.ss.clone(),
                    s.log_factory.clone(),
                    s.app.clone(),
                )
                .await;
            assert!(session_result.is_ok());
            let session = session_result.unwrap();
            assert_eq!(tc.expected, session.iss.disable_message_persist);
        }
    }
}
