use crate::session::session_state::LoggedOn;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct InSession {
    pub logged_on: LoggedOn,
}

impl ToString for InSession {
    fn to_string(&self) -> String {
        String::from("In Session")
    }
}

impl InSession {
    delegate! {
        to self.logged_on {
            pub fn is_connected(&self) -> bool;
            pub fn is_session_time(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;

        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::ERR_DO_NOT_SEND,
        field_map::FieldMap,
        fix_utc_timestamp::FIXUTCTimestamp,
        fixer_test::{
            FieldEqual, SessionSuiteRig, TestApplication, OVERRIDE_TIMES,
            OVERRIDE_TIMES_TO_APP_RETURN_ERROR,
        },
        internal::event::{NEED_HEARTBEAT, PEER_TIMEOUT},
        message::Message,
        msg_type::{
            MSG_TYPE_HEARTBEAT, MSG_TYPE_LOGOUT, MSG_TYPE_REJECT, MSG_TYPE_RESEND_REQUEST,
            MSG_TYPE_SEQUENCE_RESET, MSG_TYPE_TEST_REQUEST,
        },
        session::{
            in_session::InSession,
            pending_timeout::PendingTimeout,
            session_state::{AfterPendingTimeout, SessionStateEnum},
        },
        store::MessageStoreTrait,
        tag::{
            Tag, TAG_BEGIN_SEQ_NO, TAG_END_SEQ_NO, TAG_GAP_FILL_FLAG,
            TAG_LAST_MSG_SEQ_NUM_PROCESSED, TAG_MSG_SEQ_NUM, TAG_NEW_SEQ_NO, TAG_ORIG_SENDING_TIME,
            TAG_POSS_DUP_FLAG, TAG_REF_TAG_ID, TAG_SENDING_TIME, TAG_TEXT,
        },
    };
    use chrono::{Duration, Utc};
    use delegate::delegate;

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSuite {
                ssr: SessionSuiteRig::init(),
            };
            assert!(s.ssr.session.store.reset().await.is_ok());
            s.ssr.session.sm.state = SessionStateEnum::new_in_session();
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
        assert!(s.ssr.session.sm.is_logged_on());
        assert!(s.ssr.session.sm.is_connected());
        assert!(s.ssr.session.sm.is_session_time());
    }

    #[tokio::test]
    async fn test_logout() {
        let mut s = SessionSuite::setup_test().await;
        let mut msg = s.ssr.message_factory.logout();
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.state(SessionStateEnum::new_latent_state());

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.ssr.next_sender_msg_seq_num(2).await;
        s.ssr.next_target_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_logout_enable_last_msg_seq_num_processed() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.enable_last_msg_seq_num_processed = true;
        let mut msg = s.ssr.message_factory.logout();
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.last_to_admin_message_sent().await;

        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            FieldEqual::Num(1),
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
    async fn test_logout_reset_on_logout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.reset_on_logout = true;
        let msg = s.ssr.message_factory.new_order_single();
        assert!(s.ssr.session.queue_for_send(&msg).await.is_ok());

        let mut msg = s.ssr.message_factory.logout();
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.state(SessionStateEnum::new_latent_state());
        s.ssr.last_to_app_message_sent().await;
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );

        s.ssr.next_target_msg_seq_num(1).await;
        s.ssr.next_sender_msg_seq_num(1).await;
        s.ssr.no_message_queued().await;
    }

    #[tokio::test]
    async fn test_timeout_need_heartbeat() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;

        s.ssr.state(SessionStateEnum::new_in_session());
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_HEARTBEAT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_timeout_peer_timeout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_timeout(PEER_TIMEOUT).await;

        s.ssr
            .state(SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(InSession::default()),
            }));
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_TEST_REQUEST).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.ssr.next_sender_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_disconnected() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_disconnected().await;
        s.ssr.state(SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_stop() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_stop().await;

        s.ssr.state(SessionStateEnum::new_logout_state());
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );

        let event = s.ssr.session.session_event.rx.recv().await.unwrap();
        s.ssr.session.sm_timeout(event).await;
        s.ssr.stopped();
        s.ssr.disconnected().await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_high_enable_last_msg_seq_num_processed() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.enable_last_msg_seq_num_processed = true;
        s.ssr.message_factory.seq_num = 5;

        let mut msg_seq_num_too_high = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num_too_high).await;

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_RESEND_REQUEST).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_LAST_MSG_SEQ_NUM_PROCESSED,
            FieldEqual::Num(0),
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
    async fn test_fix_msg_in_target_too_high() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.message_factory.seq_num = 5;

        let mut msg_seq_num_too_high = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num_too_high).await;

        s.ssr.last_to_admin_message_sent().await;
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
        s.field_equals(
            TAG_END_SEQ_NO,
            FieldEqual::Num(0),
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

        let sse = s.ssr.session.sm.state.clone();

        if let SessionStateEnum::ResendState(ref rs) = sse {
            s.ssr.next_target_msg_seq_num(1).await;

            let stashed_msg_option = rs.message_stash.get(&6);
            assert!(stashed_msg_option.is_some());

            let stashed_msg = stashed_msg_option.unwrap();

            let raw_msg = msg_seq_num_too_high.build();
            let stashed_raw_msg = stashed_msg.build();

            assert_eq!(raw_msg, stashed_raw_msg);
        } else {
            assert!(false);
        }
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_high_resend_request_chunk_size() {
        struct TestCase {
            chunk_size: isize,
            expected_end_seq_no: isize,
        }

        let tests = vec![
            TestCase {
                chunk_size: 0,
                expected_end_seq_no: 0,
            },
            TestCase {
                chunk_size: 10,
                expected_end_seq_no: 0,
            },
            TestCase {
                chunk_size: 5,
                expected_end_seq_no: 0,
            },
            TestCase {
                chunk_size: 2,
                expected_end_seq_no: 2,
            },
            TestCase {
                chunk_size: 3,
                expected_end_seq_no: 3,
            },
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.message_factory.seq_num = 5;
            s.ssr.session.iss.resend_request_chunk_size = test.chunk_size;

            let mut msg_seq_num_too_high = s.ssr.message_factory.new_order_single();
            s.ssr.session.sm_fix_msg_in(&mut msg_seq_num_too_high).await;

            s.ssr.last_to_admin_message_sent().await;
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
            s.field_equals(
                TAG_END_SEQ_NO,
                FieldEqual::Num(test.expected_end_seq_no),
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

            let sse = s.ssr.session.sm.state.clone();

            if let SessionStateEnum::ResendState(ref rs) = sse {
                s.ssr.next_target_msg_seq_num(1).await;

                let stashed_msg_option = rs.message_stash.get(&6);
                assert!(stashed_msg_option.is_some());

                let stashed_msg = stashed_msg_option.unwrap();

                let raw_msg = msg_seq_num_too_high.build();
                let stashed_raw_msg = stashed_msg.build();

                assert_eq!(raw_msg, stashed_raw_msg);
            } else {
                assert!(false);
            }
        }
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_all_admin_expect_gap_fill() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();

        s.ssr.mock_app.set_to_admin(3);

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.next_sender_msg_seq_num(4).await;

        s.ssr.session.session_id.qualifier.clear();
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.resend_request(1))
            .await;

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
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
        s.field_equals(
            TAG_POSS_DUP_FLAG,
            FieldEqual::Bool(true),
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
        s.field_equals(
            TAG_NEW_SEQ_NO,
            FieldEqual::Num(4),
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
            TAG_GAP_FILL_FLAG,
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

        s.ssr.next_sender_msg_seq_num(4).await;
        s.ssr.state(SessionStateEnum::new_in_session());
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_all_admin_then_app() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();

        s.ssr.mock_app.set_to_admin(2);
        s.ssr.mock_app.set_to_app(1);

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr.last_to_app_message_sent().await;
        // 2 calls for to_admin, 1 call for to_app
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.next_sender_msg_seq_num(4).await;

        s.ssr.mock_app.set_to_admin(1);
        s.ssr.mock_app.set_to_app(1);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.resend_request(1))
            .await;

        // 1 calls for to_admin, 1 calls for to_app
        s.ssr.mock_app.write().await.mock_app.checkpoint();

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
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
        s.field_equals(
            TAG_POSS_DUP_FLAG,
            FieldEqual::Bool(true),
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
        s.field_equals(
            TAG_NEW_SEQ_NO,
            FieldEqual::Num(3),
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
            TAG_GAP_FILL_FLAG,
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

        s.ssr.last_to_app_message_sent().await;
        s.message_type(
            "D".to_string(),
            s.ssr.mock_app.read().await.last_to_app.as_ref().unwrap(),
        );

        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(3),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_app
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );
        s.field_equals(
            TAG_POSS_DUP_FLAG,
            FieldEqual::Bool(true),
            &s.ssr
                .mock_app
                .read()
                .await
                .last_to_app
                .as_ref()
                .unwrap()
                .header
                .field_map,
        );

        s.ssr.next_sender_msg_seq_num(4).await;
        s.ssr.state(SessionStateEnum::new_in_session());
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_no_message_persist() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.disable_message_persist = true;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();

        s.ssr.mock_app.set_to_app(1);
        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr.last_to_app_message_sent().await;

        // 1 call of to_app
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.next_sender_msg_seq_num(2).await;

        s.ssr.mock_app.set_to_admin(1);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.resend_request(1))
            .await;
        // 1 call of to_admin
        s.ssr.mock_app.write().await.mock_app.checkpoint();

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
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
        s.field_equals(
            TAG_POSS_DUP_FLAG,
            FieldEqual::Bool(true),
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
        s.field_equals(
            TAG_NEW_SEQ_NO,
            FieldEqual::Num(2),
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
            TAG_GAP_FILL_FLAG,
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

        s.ssr.next_sender_msg_seq_num(2).await;
        s.ssr.state(SessionStateEnum::new_in_session());
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_do_not_send_app() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_to_admin(2);
        s.ssr.mock_app.set_to_app(1);
        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        assert!(s
            .ssr
            .session
            .send(&s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr.last_to_app_message_sent().await;

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;
        s.ssr.last_to_admin_message_sent().await;

        // 2 calls of to_admin, 1 call of to_app
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.next_sender_msg_seq_num(4).await;

        // NOTE: a cheat here, need to reset mock.
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES_TO_APP_RETURN_ERROR.to_string();
        s.ssr.mock_app.set_to_admin(1);
        s.ssr.mock_app.set_to_app_return_error(1, &ERR_DO_NOT_SEND);

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.resend_request(1))
            .await;

        // 1 call of to_admin, 1 call of to_app
        s.ssr.mock_app.write().await.mock_app.checkpoint();

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_SEQUENCE_RESET).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_MSG_SEQ_NUM,
            FieldEqual::Num(1),
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
        s.field_equals(
            TAG_POSS_DUP_FLAG,
            FieldEqual::Bool(true),
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
        s.field_equals(
            TAG_NEW_SEQ_NO,
            FieldEqual::Num(4),
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
            TAG_GAP_FILL_FLAG,
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

        s.ssr.no_message_sent().await;
        s.ssr.next_sender_msg_seq_num(4).await;
        s.ssr.state(SessionStateEnum::new_in_session());
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_low() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_target_msg_seq_num().await;

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;
        s.ssr.last_to_admin_message_sent().await;
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
        s.ssr.state(SessionStateEnum::new_logout_state());
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_low_poss_dup() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.incr_next_target_msg_seq_num().await;

        let mut nos = s.ssr.message_factory.new_order_single();
        nos.header.set_field(TAG_POSS_DUP_FLAG, true);

        s.ssr.session.sm_fix_msg_in(&mut nos).await;

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_REJECT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_TEXT,
            FieldEqual::Str("Required tag missing"),
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
            TAG_REF_TAG_ID,
            FieldEqual::Num(TAG_ORIG_SENDING_TIME),
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
        s.ssr.state(SessionStateEnum::new_in_session());

        nos.header.set_field(
            TAG_ORIG_SENDING_TIME,
            FIXUTCTimestamp::from_time(Utc::now() - Duration::minutes(1)),
        );
        nos.header
            .set_field(TAG_SENDING_TIME, FIXUTCTimestamp::from_time(Utc::now()));
        s.ssr.session.sm_fix_msg_in(&mut nos).await;

        s.ssr.no_message_sent().await;
        // s.ssr.state(SessionStateEnum::new_in_session());
        // s.ssr.next_target_msg_seq_num(2).await;
    }
}
