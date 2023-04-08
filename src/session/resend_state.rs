use crate::{message::Message, session::session_state::LoggedOn};
use delegate::delegate;
use std::collections::HashMap;

#[derive(Default, Debug, Clone)]
pub struct ResendState {
    pub logged_on: LoggedOn,
    pub message_stash: HashMap<isize, Message>,
    pub current_resend_range_end: isize,
    pub resend_range_end: isize,
}

impl ToString for ResendState {
    fn to_string(&self) -> String {
        String::from("Resend")
    }
}

impl ResendState {
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
        field_map::FieldMap,
        fixer_test::{FieldEqual, SessionSuiteRig, TestApplication, OVERRIDE_TIMES},
        internal::event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
        message::Message,
        msg_type::MSG_TYPE_RESEND_REQUEST,
        session::session_state::SessionStateEnum,
        tag::{Tag, TAG_BEGIN_SEQ_NO, TAG_END_SEQ_NO},
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
            s.ssr.session.sm.state = SessionStateEnum::new_resend_state();
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
    async fn test_timeout_peer_timeout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_timeout(PEER_TIMEOUT).await;

        s.ssr
            .state(&SessionStateEnum::new_pending_timeout_resend_state());
    }

    #[tokio::test]
    async fn test_timeout_unchanged_ignore_logon_logout_timeout() {
        let mut s = SessionSuite::setup_test().await;
        let tests = vec![NEED_HEARTBEAT, LOGON_TIMEOUT, LOGOUT_TIMEOUT];

        for test in tests {
            s.ssr.session.sm_timeout(test).await;
            s.ssr.state(&SessionStateEnum::new_resend_state());
        }
    }

    #[tokio::test]
    async fn test_timeout_unchanged_need_heartbeat() {
        let mut s = SessionSuite::setup_test().await;

        s.ssr.session.sm_timeout(NEED_HEARTBEAT).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
    }

    #[tokio::test]
    async fn test_fix_msg_in() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_in_session();

        // In session expects seq number 1, send too high.
        s.ssr.message_factory.set_next_seq_num(2);

        let mut msg_seq_num2 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num2).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
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
        s.ssr.next_target_msg_seq_num(1).await;

        let mut msg_seq_num3 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num3).await;
        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(1).await;

        let mut msg_seq_num4 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num4).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(1).await;

        s.ssr.message_factory.set_next_seq_num(1);
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_from_app(4);

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.state(&SessionStateEnum::new_in_session());
        s.ssr.next_target_msg_seq_num(5).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_sequence_reset() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_in_session();

        // In session expects seq number 1, send too high.
        s.ssr.message_factory.set_next_seq_num(3);

        let mut msg_seq_num3 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num3).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
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
        s.ssr.next_target_msg_seq_num(1).await;

        s.ssr.message_factory.set_next_seq_num(1);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.sequence_reset(2))
            .await;
        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.state(&SessionStateEnum::new_resend_state());

        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_from_app(2);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.next_target_msg_seq_num(4).await;
        s.ssr.state(&SessionStateEnum::new_in_session());
    }

    #[tokio::test]
    async fn test_fix_msg_in_resend_chunk() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm.state = SessionStateEnum::new_in_session();
        s.ssr.session.iss.resend_request_chunk_size = 2;

        // In session expects seq number 1, send too high.
        s.ssr.message_factory.set_next_seq_num(4);

        let mut msg_seq_num4 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num4).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
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
        s.ssr.next_target_msg_seq_num(1).await;

        let mut msg_seq_num5 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num5).await;
        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(1).await;

        let mut msg_seq_num6 = s.ssr.message_factory.new_order_single();
        s.ssr.session.sm_fix_msg_in(&mut msg_seq_num6).await;

        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(1).await;

        s.ssr.message_factory.set_next_seq_num(1);
        s.ssr.session.session_id.qualifier = OVERRIDE_TIMES.to_string();
        s.ssr.mock_app.set_from_app(1);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(2).await;

        s.ssr.mock_app.set_from_app(1); // 1 because 2-1 is 1
        s.ssr.mock_app.set_to_admin(1);
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;
        s.ssr.mock_app.write().await.mock_app.checkpoint();
        s.ssr.state(&SessionStateEnum::new_resend_state());
        s.ssr.next_target_msg_seq_num(3).await;

        s.ssr.last_to_admin_message_sent().await;
        s.message_type(
            String::from_utf8_lossy(MSG_TYPE_RESEND_REQUEST).to_string(),
            s.ssr.mock_app.read().await.last_to_admin.as_ref().unwrap(),
        );
        s.field_equals(
            TAG_BEGIN_SEQ_NO,
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
    }
}
