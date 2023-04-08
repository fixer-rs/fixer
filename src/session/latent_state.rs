use crate::session::session_state::InSessionTime;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct LatentState {
    pub in_session_time: InSessionTime,
}

impl ToString for LatentState {
    fn to_string(&self) -> String {
        String::from("Latent State")
    }
}

impl LatentState {
    delegate! {
        to self.in_session_time {
            pub fn is_session_time(&self) -> bool;
        }
    }

    pub fn is_logged_on(&self) -> bool {
        false
    }

    pub fn is_connected(&self) -> bool {
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
            s.ssr.session.sm.state = SessionStateEnum::new_latent_state();
            s
        }
    }

    #[tokio::test]
    async fn test_preliminary() {
        let s = SessionSuite::setup_test().await;
        assert!(!s.ssr.session.sm.is_logged_on());
        assert!(!s.ssr.session.sm.is_connected());
        assert!(s.ssr.session.sm.is_session_time());
    }

    #[tokio::test]
    async fn test_disconnected() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_disconnected().await;
        s.ssr.state(&SessionStateEnum::new_latent_state());
    }

    #[tokio::test]
    async fn test_stop() {
        let mut s = SessionSuite::setup_test().await;
        s.ssr.session.sm_stop().await;
        s.ssr.stopped();
    }
}
