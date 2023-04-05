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
        application::Application,
        field_map::FieldMap,
        fixer_test::{FieldEqual, SessionSuiteRig},
        internal::event::{NEED_HEARTBEAT, PEER_TIMEOUT},
        message::Message,
        msg_type::{
            MSG_TYPE_HEARTBEAT, MSG_TYPE_LOGOUT, MSG_TYPE_RESEND_REQUEST, MSG_TYPE_TEST_REQUEST,
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
            TAG_POSS_DUP_FLAG, TAG_REF_TAG_ID, TAG_TARGET_SUB_ID, TAG_TEXT,
        },
    };
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
                fn message_equals_bytes(&self, expected_bytes: &[u8], msg: &Message);
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
        let session_id = &s.ssr.session.session_id;
        s.ssr.mock_app.to_admin(&msg, session_id);
        let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        s.ssr.mock_app.on_logout(session_id);
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let session_id = &s.ssr.session.session_id;
        let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        s.ssr.mock_app.to_admin(&msg, session_id);
        s.ssr.mock_app.on_logout(session_id);
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let mut msg = s.ssr.message_factory.new_order_single();
        let session_id = &s.ssr.session.session_id.clone();
        let _ = s.ssr.mock_app.to_app(&mut msg, session_id);
        assert!(s.ssr.session.queue_for_send(&msg).await.is_ok());

        s.ssr.mock_app.write().await.mock_app.checkpoint();

        let mut msg = s.ssr.message_factory.logout();
        let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        s.ssr.mock_app.to_admin(&msg, session_id);
        s.ssr.mock_app.on_logout(session_id);
        s.ssr.session.sm_fix_msg_in(&mut msg).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let msg = s.ssr.message_factory.new_order_single();
        let session_id = &s.ssr.session.session_id;
        s.ssr.mock_app.to_admin(&msg, session_id);
        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let msg = s.ssr.message_factory.new_order_single();
        let session_id = &s.ssr.session.session_id;
        s.ssr.mock_app.to_admin(&msg, session_id);
        s.ssr.session.sm_timeout(PEER_TIMEOUT).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let session_id = &s.ssr.session.session_id;
        s.ssr.mock_app.on_logout(session_id);
        s.ssr.session.sm_disconnected().await;
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.state(SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_stop() {
        let mut s = SessionSuite::setup_test().await;
        let msg = s.ssr.message_factory.new_order_single();
        let session_id = &s.ssr.session.session_id.clone();
        s.ssr.mock_app.to_admin(&msg, session_id);
        s.ssr.session.sm_stop().await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.state(SessionStateEnum::new_logout_state());
        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_LOGOUT).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );

        s.ssr.mock_app.on_logout(session_id);
        let event = s.ssr.session.session_event.rx.recv().await.unwrap();
        s.ssr.session.sm_timeout(event).await;
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.stopped();
        s.ssr.disconnected().await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_high_enable_last_msg_seq_num_processed() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.enable_last_msg_seq_num_processed = true;
        s.ssr.message_factory.seq_num = 5;

        let mut msg_seq_num_too_high = s.ssr.message_factory.new_order_single();
        let session_id = &s.ssr.session.session_id.clone();

        s.ssr.mock_app.to_admin(&msg_seq_num_too_high, session_id);
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num_too_high).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let session_id = &s.ssr.session.session_id.clone();
        s.ssr.mock_app.to_admin(&msg_seq_num_too_high, session_id);
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num_too_high).await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        let mut s = SessionSuite::setup_test().await;
        struct TestCase {
            chunk_size: isize,
            expected_end_seq_no: isize,
        }

        let mut tests = vec![
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

        // 	}

        for test in tests {
            // 		s.SetupTest()
            // 		s.MessageFactory.seqNum = 5
            // 		s.session.ResendRequestChunkSize = test.chunkSize

            // 		s.MockApp.On("ToAdmin")
            // 		msgSeqNumTooHigh = s.NewOrderSingle()
            // 		s.fixMsgIn(s.session, msgSeqNumTooHigh)

            s.ssr.mock_app.write().await.mock_app.checkpoint();
            s.ssr.last_to_admin_message_sent().await;
            // 		s.MessageType(string(msgTypeResendRequest), s.MockApp.lastToAdmin)
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

            // 		resendState, ok = s.session.State.(resendState)
            // 		s.True(ok)
            s.ssr.next_target_msg_seq_num(1).await;

            // 		stashedMsg, ok = resendState.messageStash[6]
            // 		s.True(ok)

            // 		rawMsg = msgSeqNumTooHigh.build()
            // 		stashedRawMsg = stashedMsg.build()
            // 		s.Equal(string(rawMsg), string(stashedRawMsg))
        }
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_all_admin_expect_gap_fill() {
        let mut s = SessionSuite::setup_test().await;
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 3)
        s.ssr.next_sender_msg_seq_num(4).await;

        // let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.fixMsgIn(s.session, s.ResendRequest(1))

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.last_to_admin_message_sent().await;
        // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
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
        // 	s.State(inSession{})
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_all_admin_then_app() {
        let mut s = SessionSuite::setup_test().await;
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.MockApp.On("ToApp").Return(nil)
        // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
        s.ssr.last_to_app_message_sent().await;

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 2)
        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
        s.ssr.next_sender_msg_seq_num(4).await;

        // let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.MockApp.On("ToApp").Return(nil)
        // 	s.fixMsgIn(s.session, s.ResendRequest(1))

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 3)
        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 2)

        s.ssr.last_to_admin_message_sent().await;
        // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
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
        // 	s.MessageType("D", s.MockApp.lastToApp)
        // 	s.field_equals(TAG_MSG_SEQ_NUM, 3, s.MockApp.lastToApp.Header)
        // 	s.field_equals(TAG_POSS_DUP_FLAG, true, s.MockApp.lastToApp.Header)

        s.ssr.next_sender_msg_seq_num(4).await;
        // 	s.State(inSession{})
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_no_message_persist() {
        let mut s = SessionSuite::setup_test().await;
        // 	s.session.DisableMessagePersist = true

        // 	s.MockApp.On("ToApp").Return(nil)
        // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
        s.ssr.last_to_app_message_sent().await;

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
        s.ssr.next_sender_msg_seq_num(2).await;

        // let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.fixMsgIn(s.session, s.ResendRequest(1))

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 1)
        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)

        s.ssr.last_to_admin_message_sent().await;
        // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
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
        // 	s.State(inSession{})
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_request_do_not_send_app() {
        let mut s = SessionSuite::setup_test().await;
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.MockApp.On("ToApp").Return(nil)
        // 	s.Require().Nil(s.session.send(s.NewOrderSingle()))
        s.ssr.last_to_app_message_sent().await;

        // 	s.session.Timeout(s.session, internal.NeedHeartbeat)
        s.ssr.last_to_admin_message_sent().await;

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 2)
        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)
        s.ssr.next_sender_msg_seq_num(4).await;

        // 	// NOTE: a cheat here, need to reset mock.
        // 	s.MockApp = MockApp{}
        // let _ = s.ssr.mock_app.from_admin(&msg, session_id);
        // 	s.MockApp.On("ToApp").Return(ErrDoNotSend)
        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.fixMsgIn(s.session, s.ResendRequest(1))

        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToAdmin", 1)
        // 	s.MockApp.AssertNumberOfCalls(s.T(), "ToApp", 1)

        s.ssr.last_to_admin_message_sent().await;
        // 	s.MessageType(string(msgTypeSequenceReset), s.MockApp.lastToAdmin)
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

        // 	s.NoMessageSent()

        s.ssr.next_sender_msg_seq_num(4).await;
        // 	s.State(inSession{})
    }

    #[tokio::test]
    async fn test_fix_msg_in_target_too_low() {
        let mut s = SessionSuite::setup_test().await;
        // 	s.incr_next_target_msg_seq_num()

        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	s.fixMsgIn(s.session, s.NewOrderSingle())
        s.ssr.mock_app.write().await.mock_app.checkpoint();
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
        // 	s.incr_next_target_msg_seq_num()

        // s.ssr.mock_app.to_admin(&msg, session_id);
        // 	nos = s.NewOrderSingle()
        // 	nos.header.set_field(tagPossDupFlag, FIXBoolean(true))

        // 	s.fixMsgIn(s.session, nos)
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.last_to_admin_message_sent().await;
        // 	s.MessageType(string(msgTypeReject), s.MockApp.lastToAdmin)
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
        // 	s.State(inSession{})

        // 	nos.header.set_field(tagOrigSendingTime, FIXUTCTimestamp{Time: time.Now().Add(time.Duration(-1) * time.Minute)})
        // 	nos.header.set_field(tagSendingTime, FIXUTCTimestamp{Time: time.Now()})
        // 	s.fixMsgIn(s.session, nos)
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        // 	s.NoMessageSent()
        // 	s.State(inSession{})
        s.ssr.next_target_msg_seq_num(2).await;
    }
}
