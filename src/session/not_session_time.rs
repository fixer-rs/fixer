use crate::internal::event::Event;
use crate::message::Message;
use crate::session::latent_state::LatentState;
use crate::session::{
    session_state::{ConnectedNotLoggedOn, SessionState},
    Session,
};
use async_trait::async_trait;
use delegate::delegate;

pub struct NotSessionTime {
    pub latent_state: LatentState,
}

impl ToString for NotSessionTime {
    fn to_string(&self) -> String {
        String::from("Not session time")
    }
}

#[async_trait]
impl SessionState for NotSessionTime {
    delegate! {
        to self.latent_state {
            fn is_connected(&self) -> bool;
            fn is_logged_on(&self) -> bool;
            fn shutdown_now(&self, _session: &Session);
        }
    }

    fn is_session_time(&self) -> bool {
        false
    }

    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> Box<dyn SessionState> {
        session.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        Box::new(self)
    }

    fn timeout(self, _session: &mut Session, _event: Event) -> Box<dyn SessionState> {
        Box::new(self)
    }

    fn stop(self, _session: &mut Session) -> Box<dyn SessionState> {
        Box::new(self)
    }
}

#[cfg(test)]
mod tests {
    // type NotSessionTimeTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestNotSessionTime(t *testing.T) {
    // 	suite.Run(t, new(NotSessionTimeTestSuite))
    // }

    // func (s *NotSessionTimeTestSuite) SetupTest() {
    // 	s.Init()
    // 	s.session.State = notSessionTime{}
    // }

    // func (s *NotSessionTimeTestSuite) TestPreliminary() {
    // 	s.False(s.session.IsLoggedOn())
    // 	s.False(s.session.IsConnected())
    // 	s.False(s.session.IsSessionTime())
    // }

    // func (s *NotSessionTimeTestSuite) TestDisconnected() {
    // 	s.session.Disconnected(s.session)
    // 	s.State(notSessionTime{})
    // }

    // func (s *NotSessionTimeTestSuite) TestStop() {
    // 	s.session.Stop(s.session)
    // 	s.Stopped()
    // }
}
