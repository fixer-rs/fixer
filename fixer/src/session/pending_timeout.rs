use crate::session::session_state::AfterPendingTimeout;
use delegate::delegate;

#[derive(Debug, Clone)]
pub struct PendingTimeout {
    pub session_state: AfterPendingTimeout,
}

impl std::fmt::Display for PendingTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.session_state {
            AfterPendingTimeout::InSession(is) => write!(f, "{is}"),
            AfterPendingTimeout::ResendState(rs) => write!(f, "{rs}"),
        }
    }
}

impl PendingTimeout {
    delegate! {
        to match &self.session_state {
            AfterPendingTimeout::InSession(is) => is,
            AfterPendingTimeout::ResendState(rs) => rs,
        } {
            pub fn is_connected(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
            pub fn is_session_time(&self) -> bool ;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unused_async)]
mod tests {
    use crate::{
        fixer_test::SessionSuiteRig,
        session::event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
        session::session_state::SessionStateEnum,
    };

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            SessionSuite {
                ssr: SessionSuiteRig::init(),
            }
        }
    }

    #[tokio::test]
    async fn test_is_connected_is_logged_on() {
        let tests = vec![
            SessionStateEnum::new_pending_timeout_in_session(),
            SessionStateEnum::new_pending_timeout_resend_state(),
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test;
            assert!(s.ssr.session.sm.is_logged_on());
            assert!(s.ssr.session.sm.is_connected());
        }
    }

    #[tokio::test]
    async fn test_session_timeout() {
        let tests = vec![
            SessionStateEnum::new_pending_timeout_in_session(),
            SessionStateEnum::new_pending_timeout_resend_state(),
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test;

            s.ssr.session.sm_timeout(PEER_TIMEOUT).await;
            s.ssr.state(&SessionStateEnum::new_latent_state());
        }
    }

    #[tokio::test]
    async fn test_timeout_unchanged_state() {
        let tests = vec![
            SessionStateEnum::new_pending_timeout_in_session(),
            SessionStateEnum::new_pending_timeout_resend_state(),
        ];

        let test_events = [NEED_HEARTBEAT, LOGON_TIMEOUT, LOGOUT_TIMEOUT];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.clone();

            for event in &test_events {
                s.ssr.session.sm_timeout(*event).await;
                s.ssr.state(&test);
            }
        }
    }

    #[tokio::test]
    async fn test_disconnected() {
        let tests = vec![
            SessionStateEnum::new_pending_timeout_in_session(),
            SessionStateEnum::new_pending_timeout_resend_state(),
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test;

            s.ssr.session.sm_disconnected().await;

            s.ssr.state(&SessionStateEnum::new_latent_state());
        }
    }
}
