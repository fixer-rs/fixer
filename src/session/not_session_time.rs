use crate::internal::event::Event;
use crate::message::Message;
use crate::session::latent_state::LatentState;
use crate::session::{
    session_state::{ConnectedNotLoggedOn, SessionStateEnum},
    Session,
};
use delegate::delegate;

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
            pub fn shutdown_now(&self, _session: &Session);
        }
    }

    pub fn is_session_time(&self) -> bool {
        false
    }

    pub async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> SessionStateEnum {
        session.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        todo!()
        // Box::new(self)
    }

    pub fn timeout(self, _session: &mut Session, _event: Event) -> SessionStateEnum {
        todo!()
        // Box::new(self)
    }

    pub fn stop(self, _session: &mut Session) -> SessionStateEnum {
        // Box::new(self)
        todo!()
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
