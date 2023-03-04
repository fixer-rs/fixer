// import "github.com/quickfixgo/quickfix/internal"

// type notSessionTime struct{ latentState }

// func (notSessionTime) String() string      { return "Not session time" }
// func (notSessionTime) IsSessionTime() bool { return false }

// func (state notSessionTime) FixMsgIn(session *session, msg *Message) (nextState sessionState) {
// 	session.log.OnEventf("Invalid Session State: Unexpected Msg %v while in Latent state", msg)
// 	return state
// }

// func (state notSessionTime) Timeout(*session, internal.Event) (nextState sessionState) {
// 	return state
// }

// func (state notSessionTime) Stop(*session) (nextState sessionState) {
// 	return state
// }

#[cfg(test)]
mod tests {

    // import (
    // 	"testing"

    // 	"github.com/stretchr/testify/suite"
    // )

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
