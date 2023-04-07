use crate::session::session_state::ConnectedNotLoggedOn;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct LogonState {
    connected_not_logged_on: ConnectedNotLoggedOn,
}

impl ToString for LogonState {
    fn to_string(&self) -> String {
        String::from("Logon State")
    }
}

impl LogonState {
    delegate! {
        to self.connected_not_logged_on {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::{MessageRejectErrorEnum, RejectLogon},
        field_map::FieldMap,
        fix_boolean::FIXBoolean,
        fix_int::FIXInt,
        fixer_test::{
            FieldEqual, SessionSuiteRig, TestApplication, OVERRIDE_TIMES,
            OVERRIDE_TIMES_FROM_ADMIN_RETURN_ERROR,
        },
        internal::event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT},
        message::Message,
        msg_type::{MSG_TYPE_LOGON, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST},
        session::{resend_state::ResendState, session_state::SessionStateEnum},
        store::MessageStoreTrait,
        tag::{
            Tag, TAG_BEGIN_SEQ_NO, TAG_HEART_BT_INT, TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            TAG_MSG_SEQ_NUM, TAG_RESET_SEQ_NUM_FLAG, TAG_TEXT,
        },
    };
    use chrono::Duration;
    use delegate::delegate;

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSuite {
                ssr: SessionSuiteRig::init(),
            };
            s.ssr.session.sm.state = SessionStateEnum::new_logon_state();
            s
        }

        delegate! {
            to self.ssr.suite {
                fn message_type(&self, msg_type: String, msg: &Message);
                fn field_equals<'a>(&self, tag: Tag, expected_value: FieldEqual<'a>, field_map: &FieldMap);
            }
        }
    }

    #[tokio::test]
    async fn test_preliminary() {
        let s = SessionSuite::setup_test().await;
        assert!(!s.ssr.session.sm.is_logged_on());
        assert!(s.ssr.session.sm.is_connected());
        assert!(s.ssr.session.sm.is_session_time());
    }

    #[tokio::test]
    async fn test_timeout_logon_timeout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_timeout(LOGON_TIMEOUT).await;
        s.ssr.state(SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_timeout_logon_timeout_initiated_logon() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.initiate_logon = true;

        s.ssr.session.sm_timeout(LOGON_TIMEOUT).await;

        s.ssr.state(SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_timeout_not_logon_timeout() {
        let mut s = SessionSuite::setup_test().await;
        let tests = vec![NEED_HEARTBEAT, LOGON_TIMEOUT, LOGOUT_TIMEOUT];

        for test in tests {
            s.ssr.session.sm_timeout(test).await;
            s.ssr.state(SessionStateEnum::new_logon_state());
        }
    }

    #[tokio::test]
    async fn test_disconnected() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_disconnected().await;
        s.ssr.state(SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_fix_msg_in_not_logon() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.state(SessionStateEnum::new_latent_state());
        s.ssr.next_target_msg_seq_num(1).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.message_factory.seq_num = 1;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        assert!(s.ssr.session.iss.heart_bt_int.is_zero());
        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());
        assert_eq!(Duration::seconds(32), s.ssr.session.iss.heart_bt_int); // Should be written from logon message.
        assert!(!s.ssr.session.iss.heart_bt_int_override);

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_HEART_BT_INT,
            FieldEqual::Num(32),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.next_target_msg_seq_num(3).await;
        s.ssr.next_sender_msg_seq_num(3).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_heart_bt_int_override() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.message_factory.seq_num = 1;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        s.ssr.session.iss.heart_bt_int_override = true;
        s.ssr.session.iss.heart_bt_int = Duration::seconds(1);
        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());
        assert_eq!(Duration::seconds(1), s.ssr.session.iss.heart_bt_int); // Should not have changed.
        assert!(s.ssr.session.iss.heart_bt_int_override);

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_HEART_BT_INT,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.next_target_msg_seq_num(3).await;
        s.ssr.next_sender_msg_seq_num(3).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_enable_last_msg_seq_num_processed() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.enable_last_msg_seq_num_processed = true;

        s.ssr.message_factory.set_next_seq_num(2);
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            FieldEqual::Num(2),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_reset_seq_num() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);
        logon
            .body
            .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());
        assert_eq!(Duration::seconds(32), s.ssr.session.iss.heart_bt_int);

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_HEART_BT_INT,
            FieldEqual::Num(32),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );
        s.field_equals(
            TAG_RESET_SEQ_NUM_FLAG,
            FieldEqual::Bool(true),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_initiate_logon() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.initiate_logon = true;
        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.message_factory.seq_num = 1;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());

        s.ssr.next_target_msg_seq_num(3).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_initiate_logon_expect_reset_seq_num() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.initiate_logon = true;
        s.ssr.session.sent_reset = true;
        assert!(s
            .ssr
            .session
            .store
            .incr_next_sender_msg_seq_num()
            .await
            .is_ok());

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);
        logon
            .body
            .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());

        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_initiate_logon_un_expected_reset_seq_num() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.initiate_logon = true;
        s.ssr.session.sent_reset = false;
        s.ssr.incr_next_target_msg_seq_num().await;
        s.ssr.incr_next_sender_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);
        logon
            .body
            .set_field(TAG_RESET_SEQ_NUM_FLAG, true as FIXBoolean);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_in_session());

        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.next_sender_msg_seq_num(1).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_refresh_on_logon() {
        let tests = vec![true, false];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.iss.refresh_on_logon = test;

            let mut logon = s.ssr.message_factory.logon();
            logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

            s.ssr.session.sm_fix_msg_in(&mut logon).await;
        }
    }

    #[tokio::test]
    async fn test_stop() {
        let tests = vec![true, false];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.iss.initiate_logon = test;

            s.ssr.session.sm_stop().await;
            s.ssr.disconnected().await;
            s.ssr.stopped();
        }
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_reject_logon() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES_FROM_ADMIN_RETURN_ERROR.to_string();
        s.ssr.mock_app.set_from_admin_return_error(
            1,
            MessageRejectErrorEnum::RejectLogon(RejectLogon {
                text: String::from("reject message"),
            }),
        );

        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.message_factory.seq_num = 1;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();

        s.ssr.state(SessionStateEnum::new_latent_state());

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_TEXT,
            FieldEqual::Str("reject message"),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.next_target_msg_seq_num(3).await;
        s.ssr.next_sender_msg_seq_num(3).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_seq_num_too_high() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_to_admin(2);

        s.ssr.message_factory.set_next_seq_num(6);
        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);

        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr
            .state(SessionStateEnum::ResendState(ResendState::default()));
        s.ssr.next_target_msg_seq_num(1).await;

        // Session should send logon, and then queues resend request for send.
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        let msg_bytes_sent_option = s.ssr.receiver.last_message().await;
        assert!(msg_bytes_sent_option.is_some());
        let msg_bytes_sent = msg_bytes_sent_option.unwrap();

        let mut sent_message = Message::new();
        let res = sent_message.parse_message(&msg_bytes_sent);
        assert!(res.is_ok());
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGON).to_string(),
            &sent_message,
        );
        s.ssr.session.send_queued().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_RESEND_REQUEST).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_BEGIN_SEQ_NO,
            FieldEqual::Num(1),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );

        s.ssr.session.session_id.qualifier.clear();
        s.ssr.message_factory.set_next_seq_num(1);

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.sequence_reset(3))
            .await;
        s.ssr
            .state(SessionStateEnum::ResendState(ResendState::default()));
        s.ssr.next_target_msg_seq_num(3).await;

        s.ssr.message_factory.set_next_seq_num(3);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.sequence_reset(7))
            .await;
        s.ssr.state(SessionStateEnum::new_in_session());
        s.ssr.next_target_msg_seq_num(7).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logon_seq_num_too_low() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_to_admin(1);

        s.ssr.incr_next_sender_msg_seq_num().await;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut logon = s.ssr.message_factory.logon();
        logon.body.set_field(TAG_HEART_BT_INT, 32 as FIXInt);
        logon.header.set_int(TAG_MSG_SEQ_NUM, 1 as FIXInt);

        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.session.sm_fix_msg_in(&mut logon).await;

        s.ssr.state(SessionStateEnum::new_latent_state());
        s.ssr.next_target_msg_seq_num(2).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        let msg_bytes_sent_option = s.ssr.receiver.last_message().await;
        assert!(msg_bytes_sent_option.is_some());
        let msg_bytes_sent = msg_bytes_sent_option.unwrap();

        let mut sent_message = Message::new();
        let res = sent_message.parse_message(&msg_bytes_sent);
        assert!(res.is_ok());
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            &sent_message,
        );

        s.ssr.session.send_queued().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );

        s.field_equals(
            TAG_TEXT,
            FieldEqual::Str("MsgSeqNum too low, expecting 2 but received 1"),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_admin
                .as_ref()
                .unwrap()
                .body
                .field_map,
        );
    }
}
