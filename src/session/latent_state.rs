use crate::{
    internal::event::Event,
    log::LogTrait,
    message::Message,
    session::{
        session_state::{InSessionTime, SessionStateEnum},
        Session,
    },
};
use delegate::delegate;

#[derive(Default)]
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

    pub async fn fix_msg_in(
        self,
        session: &'_ mut Session,
        msg: &'_ mut Message,
    ) -> SessionStateEnum {
        session.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        SessionStateEnum::LatentState(self)
    }

    pub async fn timeout(self, _session: &mut Session, _event: Event) -> SessionStateEnum {
        SessionStateEnum::LatentState(self)
    }

    pub fn is_logged_on(&self) -> bool {
        false
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub async fn shutdown_now(&self, _session: &mut Session) {}

    pub async fn stop(self, _session: &mut Session) -> SessionStateEnum {
        SessionStateEnum::LatentState(self)
    }
}

#[cfg(test)]
mod tests {
    // type LatentStateTestSuite struct {
    //     SessionSuiteRig
    // }

    // func TestLatentStateTestSuite(t *testing.T) {
    //     suite.Run(t, new(LatentStateTestSuite))
    // }

    // func (s *LatentStateTestSuite) SetupTest() {
    //     s.Init()
    //     s.session.State = latentState{}
    // }

    // func (s *LatentStateTestSuite) TestPreliminary() {
    //     s.False(s.session.IsLoggedOn())
    //     s.False(s.session.IsConnected())
    //     s.True(s.session.IsSessionTime())
    // }

    // func (s *LatentStateTestSuite) TestDisconnected() {
    //     s.session.Disconnected(s.session)
    //     s.State(latentState{})
    // }

    // func (s *LatentStateTestSuite) TestStop() {
    //     s.session.Stop(s.session)
    //     s.Stopped()
    // }
}
