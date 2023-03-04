// package quickfix

// import "github.com/quickfixgo/quickfix/internal"

// type latentState struct{ inSessionTime }

// func (state latentState) String() string    { return "Latent State" }
// func (state latentState) IsLoggedOn() bool  { return false }
// func (state latentState) IsConnected() bool { return false }

// func (state latentState) FixMsgIn(session *session, msg *Message) (nextState sessionState) {
// 	session.log.OnEventf("Invalid Session State: Unexpected Msg %v while in Latent state", msg)
// 	return state
// }

// func (state latentState) Timeout(*session, internal.Event) (nextState sessionState) {
// 	return state
// }

// func (state latentState) ShutdownNow(*session) {}
// func (state latentState) Stop(*session) (nextState sessionState) {
// 	return state
// }

#[cfg(test)]
mod tests {

    // import (
    //     "testing"

    //     "github.com/stretchr/testify/suite"
    // )

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
