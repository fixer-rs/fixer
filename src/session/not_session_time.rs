use crate::session::latent_state::LatentState;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct NotSessionTime {
    pub latent_state: LatentState,
}

impl ToString for NotSessionTime {
    fn to_string(&self) -> String {
        String::from("Not session time")
    }
}

impl NotSessionTime {
    delegate! {
        to self.latent_state {
            pub fn is_connected(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
        }
    }

    pub fn is_session_time(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::{fixer_test::SessionSuiteRig, session::session_state::SessionStateEnum};

    struct SessionSuite {
        ssr: SessionSuiteRig,
    }

    impl SessionSuite {
        async fn setup_test() -> Self {
            let mut s = SessionSuite {
                ssr: SessionSuiteRig::init(),
            };
            s.ssr.session.sm.state = SessionStateEnum::new_not_session_time();
            s
        }
    }

    #[tokio::test]
    async fn test_preliminary() {
        let s = SessionSuite::setup_test().await;
        assert!(!s.ssr.session.sm.is_logged_on());
        assert!(!s.ssr.session.sm.is_connected());
        assert!(!s.ssr.session.sm.is_session_time());
    }

    #[tokio::test]
    async fn test_disconnected() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_disconnected().await;
        s.ssr.state(SessionStateEnum::new_not_session_time());
    }

    #[tokio::test]
    async fn test_stop() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_stop().await;
        s.ssr.stopped();
    }
}
