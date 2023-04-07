use crate::session::session_state::AfterPendingTimeout;
use delegate::delegate;

#[derive(Debug, Clone)]
pub struct PendingTimeout {
    pub session_state: AfterPendingTimeout,
}

impl PendingTimeout {
    delegate! {
        to match &self.session_state {
            AfterPendingTimeout::InSession(is) => is,
            AfterPendingTimeout::ResendState(rs) => rs,
        } {
            pub fn to_string(&self) -> String;
            pub fn is_connected(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
            pub fn is_session_time(&self) -> bool ;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        fixer_test::SessionSuiteRig,
        internal::event::{LOGON_TIMEOUT, LOGOUT_TIMEOUT, NEED_HEARTBEAT, PEER_TIMEOUT},
        session::{
            in_session::InSession,
            pending_timeout::PendingTimeout,
            resend_state::ResendState,
            session_state::{AfterPendingTimeout, SessionStateEnum},
        },
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
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(InSession::default()),
            }),
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(ResendState::default()),
            }),
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
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(InSession::default()),
            }),
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(ResendState::default()),
            }),
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test;

            s.ssr.session.sm_timeout(PEER_TIMEOUT).await;
            s.ssr.state(SessionStateEnum::new_latent_state());
        }
    }

    #[tokio::test]
    async fn test_timeout_unchanged_state() {
        let tests = vec![
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(InSession::default()),
            }),
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(ResendState::default()),
            }),
        ];

        let test_events = vec![NEED_HEARTBEAT, LOGON_TIMEOUT, LOGOUT_TIMEOUT];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test.clone();

            for event in test_events.iter() {
                s.ssr.session.sm_timeout(*event).await;
                s.ssr.state(test.clone());
            }
        }
    }

    #[tokio::test]
    async fn test_disconnected() {
        let tests = vec![
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::InSession(InSession::default()),
            }),
            SessionStateEnum::PendingTimeout(PendingTimeout {
                session_state: AfterPendingTimeout::ResendState(ResendState::default()),
            }),
        ];

        for test in tests {
            let mut s = SessionSuite::setup_test().await;
            s.ssr.session.sm.state = test;

            s.ssr.disconnected().await;

            s.ssr.state(SessionStateEnum::new_latent_state());
        }
    }
}
