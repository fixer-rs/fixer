use crate::session::session_state::ConnectedNotLoggedOn;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct LogoutState {
    connected_not_logged_on: ConnectedNotLoggedOn,
}

impl ToString for LogoutState {
    fn to_string(&self) -> String {
        String::from("Logout State")
    }
}

impl LogoutState {
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
    use std::sync::Arc;

    use crate::{
        errors::conditionally_required_field_missing,
        fixer_test::{SessionSuiteRig, TestApplication, FROM_APP_RETURN_ERROR},
        internal::event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
        session::session_state::SessionStateEnum,
        tag::Tag,
    };

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSuite {
                ssr: SessionSuiteRig::init(),
            };
            s.ssr.session.sm.state = SessionStateEnum::new_logout_state();
            s
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
    async fn test_timeout_logout_timeout() {
        let mut s = SessionSuite::setup_test().await;

        s.ssr.session.sm_timeout(LOGOUT_TIMEOUT).await;

        s.ssr.state(&SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_timeout_not_logout_timeout() {
        let mut s = SessionSuite::setup_test().await;
        let tests = vec![PEER_TIMEOUT, NEED_HEARTBEAT, LOGON_TIMEOUT];

        for test in tests {
            s.ssr.session.sm_timeout(test).await;
            s.ssr.state(&SessionStateEnum::new_logout_state());
        }
    }

    #[tokio::test]
    async fn test_disconnected() {
        let mut s = SessionSuite::setup_test().await;

        s.ssr.session.sm_disconnected().await;

        s.ssr.state(&SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_fix_msg_in_not_logout() {
        let mut s = SessionSuite::setup_test().await;

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.state(&SessionStateEnum::new_logout_state());
        s.ssr.next_target_msg_seq_num(2).await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_not_logout_reject() {
        let mut s = SessionSuite::setup_test().await;

        let mut session_id = (*s.ssr.session.session_id).clone();
        session_id.qualifier = FROM_APP_RETURN_ERROR.to_string();
        s.ssr.session.session_id = Arc::new(session_id);

        let error = conditionally_required_field_missing(11 as Tag);
        s.ssr.mock_app.set_from_app_return_error(1, error);

        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.new_order_single())
            .await;

        s.ssr.state(&SessionStateEnum::new_logout_state());
        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.next_sender_msg_seq_num(2).await;

        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.logout())
            .await;

        s.ssr.state(&SessionStateEnum::new_latent_state());
        s.ssr.next_target_msg_seq_num(2).await;
        s.ssr.next_sender_msg_seq_num(1).await;
        s.ssr.no_message_sent().await;
    }

    #[tokio::test]
    async fn test_fix_msg_in_logout_reset_on_logout() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.iss.reset_on_logout = true;

        assert!(s
            .ssr
            .session
            .queue_for_send(&mut s.ssr.message_factory.new_order_single())
            .await
            .is_ok());
        s.ssr
            .session
            .sm_fix_msg_in(&mut s.ssr.message_factory.logout())
            .await;

        s.ssr.state(&SessionStateEnum::new_latent_state());
        s.ssr.next_target_msg_seq_num(1).await;
        s.ssr.next_sender_msg_seq_num(1).await;

        s.ssr.no_message_sent().await;
        s.ssr.no_message_queued().await;
    }

    #[tokio::test]
    async fn test_stop() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_stop().await;
        s.ssr.state(&SessionStateEnum::new_logout_state());
        s.ssr.not_stopped();
    }
}
