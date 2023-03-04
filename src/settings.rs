// package quickfix

// import (
// 	"bufio"
// 	"errors"
// 	"fmt"
// 	"io"
// 	"regexp"

// 	"github.com/quickfixgo/quickfix/config"
// )

// // The Settings type represents a collection of global and session settings.
// type Settings struct {
// 	globalSettings  *SessionSettings
// 	sessionSettings map[SessionID]*SessionSettings
// }

// // Init initializes or resets a Settings instance.
// func (s *Settings) Init() {
// 	s.globalSettings = NewSessionSettings()
// 	s.sessionSettings = make(map[SessionID]*SessionSettings)
// }

// func (s *Settings) lazyInit() {
// 	if s.globalSettings == nil {
// 		s.Init()
// 	}
// }

// // NewSettings creates a Settings instance.
// func NewSettings() *Settings {
// 	s := &Settings{}
// 	s.Init()
// 	return s
// }

// func sessionIDFromSessionSettings(globalSettings *SessionSettings, sessionSettings *SessionSettings) SessionID {
// 	sessionID := SessionID{}

// 	for _, settings := range []*SessionSettings{globalSettings, sessionSettings} {
// 		if settings.HasSetting(config.BeginString) {
// 			sessionID.BeginString, _ = settings.Setting(config.BeginString)
// 		}

// 		if settings.HasSetting(config.TargetCompID) {
// 			sessionID.TargetCompID, _ = settings.Setting(config.TargetCompID)
// 		}

// 		if settings.HasSetting(config.TargetSubID) {
// 			sessionID.TargetSubID, _ = settings.Setting(config.TargetSubID)
// 		}

// 		if settings.HasSetting(config.TargetLocationID) {
// 			sessionID.TargetLocationID, _ = settings.Setting(config.TargetLocationID)
// 		}

// 		if settings.HasSetting(config.SenderCompID) {
// 			sessionID.SenderCompID, _ = settings.Setting(config.SenderCompID)
// 		}

// 		if settings.HasSetting(config.SenderSubID) {
// 			sessionID.SenderSubID, _ = settings.Setting(config.SenderSubID)
// 		}

// 		if settings.HasSetting(config.SenderLocationID) {
// 			sessionID.SenderLocationID, _ = settings.Setting(config.SenderLocationID)
// 		}

// 		if settings.HasSetting(config.SessionQualifier) {
// 			sessionID.Qualifier, _ = settings.Setting(config.SessionQualifier)
// 		}
// 	}

// 	return sessionID
// }

// // ParseSettings creates and initializes a Settings instance with config parsed from a Reader.
// // Returns error if the config is has parse errors.
// func ParseSettings(reader io.Reader) (*Settings, error) {
// 	s := NewSettings()

// 	scanner := bufio.NewScanner(reader)
// 	blankRegEx := regexp.MustCompile(`^\s*$`)
// 	commentRegEx := regexp.MustCompile(`^#.*`)
// 	defaultRegEx := regexp.MustCompile(`^\[(?i)DEFAULT\]\s*$`)
// 	sessionRegEx := regexp.MustCompile(`^\[(?i)SESSION\]\s*$`)
// 	settingRegEx := regexp.MustCompile(`^([^=]*)=(.*)$`)

// 	var settings *SessionSettings

// 	lineNumber := 0
// 	for scanner.Scan() {
// 		lineNumber++
// 		line := scanner.Text()

// 		switch {
// 		case commentRegEx.MatchString(line) || blankRegEx.MatchString(line):
// 			continue

// 		case defaultRegEx.MatchString(line):
// 			settings = s.GlobalSettings()

// 		case sessionRegEx.MatchString(line):
// 			if settings != nil && settings != s.GlobalSettings() {
// 				if _, err := s.AddSession(settings); err != nil {
// 					return nil, err
// 				}
// 			}
// 			settings = NewSessionSettings()

// 		case settingRegEx.MatchString(line):
// 			parts := settingRegEx.FindStringSubmatch(line)
// 			settings.Set(parts[1], parts[2])

// 		default:
// 			return s, fmt.Errorf("error parsing line %v", lineNumber)
// 		}
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return s, err
// 	}

// 	if settings == nil || settings == s.GlobalSettings() {
// 		return s, fmt.Errorf("no sessions declared")
// 	}
// 	_, err := s.AddSession(settings)

// 	return s, err
// }

// // GlobalSettings are default setting inherited by all session settings.
// func (s *Settings) GlobalSettings() *SessionSettings {
// 	s.lazyInit()
// 	return s.globalSettings
// }

// // SessionSettings return all session settings overlaying globalsettings.
// func (s *Settings) SessionSettings() map[SessionID]*SessionSettings {
// 	allSessionSettings := make(map[SessionID]*SessionSettings)

// 	for sessionID, settings := range s.sessionSettings {
// 		cloneSettings := s.globalSettings.clone()
// 		cloneSettings.overlay(settings)
// 		allSessionSettings[sessionID] = cloneSettings
// 	}

// 	return allSessionSettings
// }

// // AddSession adds Session Settings to Settings instance. Returns an error if session settings with duplicate sessionID has already been added.
// func (s *Settings) AddSession(sessionSettings *SessionSettings) (SessionID, error) {
// 	s.lazyInit()

// 	sessionID := sessionIDFromSessionSettings(s.GlobalSettings(), sessionSettings)

// 	switch sessionID.BeginString {
// 	case BeginStringFIX40:
// 	case BeginStringFIX41:
// 	case BeginStringFIX42:
// 	case BeginStringFIX43:
// 	case BeginStringFIX44:
// 	case BeginStringFIXT11:
// 	default:
// 		return sessionID, errors.New("BeginString must be FIX.4.0 to FIX.4.4 or FIXT.1.1")
// 	}

// 	if _, dup := s.sessionSettings[sessionID]; dup {
// 		return sessionID, fmt.Errorf("duplicate session configured for %v", sessionID)
// 	}

// 	s.sessionSettings[sessionID] = sessionSettings

// 	return sessionID, nil
// }

#[cfg(test)]
mod tests {

    // import (
    // 	"strings"
    // 	"testing"

    // 	"github.com/stretchr/testify/assert"
    // 	"github.com/stretchr/testify/require"
    // 	"github.com/stretchr/testify/suite"

    // 	"github.com/quickfixgo/quickfix/config"
    // )

    // func TestSettings_New(t *testing.T) {
    // 	s := NewSettings()
    // 	assert.NotNil(t, s)

    // 	globalSettings := s.GlobalSettings()
    // 	assert.NotNil(t, globalSettings)

    // 	sessionSettings := s.SessionSettings()
    // 	assert.NotNil(t, sessionSettings)
    // 	assert.Empty(t, sessionSettings)
    // }

    // type SettingsAddSessionSuite struct {
    // 	suite.Suite
    // 	settings *Settings
    // }

    // func TestSettingsAddSessionSuite(t *testing.T) {
    // 	suite.Run(t, new(SettingsAddSessionSuite))
    // }

    // func (s *SettingsAddSessionSuite) SetupTest() {
    // 	s.settings = NewSettings()
    // }

    // func (s *SettingsAddSessionSuite) TestBeginStringValidation() {
    // 	ss := NewSessionSettings()
    // 	ss.Set(config.SenderCompID, "CB")
    // 	ss.Set(config.TargetCompID, "SS")

    // 	_, err := s.settings.AddSession(ss)
    // 	s.NotNil(err)

    // 	ss.Set(config.BeginString, "NotAValidBeginString")
    // 	_, err = s.settings.AddSession(ss)
    // 	s.NotNil(err)

    // 	var cases = []string{
    // 		BeginStringFIX40,
    // 		BeginStringFIX41,
    // 		BeginStringFIX42,
    // 		BeginStringFIX43,
    // 		BeginStringFIX44,
    // 		BeginStringFIXT11,
    // 	}

    // 	for _, beginString := range cases {
    // 		ss.Set(config.BeginString, beginString)
    // 		sid, err := s.settings.AddSession(ss)
    // 		s.Nil(err)
    // 		s.Equal(sid, SessionID{BeginString: beginString, SenderCompID: "CB", TargetCompID: "SS"})
    // 	}
    // }

    // func (s *SettingsAddSessionSuite) TestGlobalOverlay() {
    // 	globalSettings := s.settings.GlobalSettings()
    // 	globalSettings.Set(config.BeginString, "FIX.4.0")
    // 	globalSettings.Set(config.SocketAcceptPort, "1000")

    // 	s1 := NewSessionSettings()
    // 	s1.Set(config.BeginString, "FIX.4.1")
    // 	s1.Set(config.SenderCompID, "CB")
    // 	s1.Set(config.TargetCompID, "SS")

    // 	s2 := NewSessionSettings()
    // 	s2.Set(config.ResetOnLogon, "Y")
    // 	s2.Set(config.SenderCompID, "CB")
    // 	s2.Set(config.TargetCompID, "SS")

    // 	sessionID1 := SessionID{BeginString: "FIX.4.1", SenderCompID: "CB", TargetCompID: "SS"}
    // 	sessionID2 := SessionID{BeginString: "FIX.4.0", SenderCompID: "CB", TargetCompID: "SS"}

    // 	var addCases = []struct {
    // 		settings          *SessionSettings
    // 		expectedSessionID SessionID
    // 	}{
    // 		{s1, sessionID1},
    // 		{s2, sessionID2},
    // 	}

    // 	for _, tc := range addCases {
    // 		sid, err := s.settings.AddSession(tc.settings)
    // 		s.Nil(err)
    // 		s.Equal(sid, tc.expectedSessionID)
    // 	}

    // 	var cases = []struct {
    // 		sessionID SessionID
    // 		input     string
    // 		expected  string
    // 	}{
    // 		{sessionID1, config.BeginString, "FIX.4.1"},
    // 		{sessionID1, config.SocketAcceptPort, "1000"},
    // 		{sessionID2, config.BeginString, "FIX.4.0"},
    // 		{sessionID2, config.SocketAcceptPort, "1000"},
    // 		{sessionID2, config.ResetOnLogon, "Y"},
    // 	}

    // 	sessionSettings := s.settings.SessionSettings()
    // 	s.Len(sessionSettings, 2)
    // 	for _, tc := range cases {
    // 		settings := sessionSettings[tc.sessionID]

    // 		actual, err := settings.Setting(tc.input)
    // 		s.Nil(err)
    // 		s.Equal(actual, tc.expected)
    // 	}
    // }

    // func (s *SettingsAddSessionSuite) TestRejectDuplicate() {
    // 	s1 := NewSessionSettings()
    // 	s1.Set(config.BeginString, "FIX.4.1")
    // 	s1.Set(config.SenderCompID, "CB")
    // 	s1.Set(config.TargetCompID, "SS")

    // 	s2 := NewSessionSettings()
    // 	s2.Set(config.BeginString, "FIX.4.0")
    // 	s2.Set(config.SenderCompID, "CB")
    // 	s2.Set(config.TargetCompID, "SS")

    // 	_, err := s.settings.AddSession(s1)
    // 	s.Nil(err)
    // 	_, err = s.settings.AddSession(s2)
    // 	s.Nil(err)

    // 	s3 := NewSessionSettings()
    // 	s1.Set(config.BeginString, "FIX.4.0")
    // 	s3.Set(config.SenderCompID, "CB")
    // 	s3.Set(config.TargetCompID, "SS")
    // 	_, err = s.settings.AddSession(s3)
    // 	s.NotNil(err, "Expected error for adding duplicate session")

    // 	sessionSettings := s.settings.SessionSettings()
    // 	s.Len(sessionSettings, 2)
    // }

    // func TestSettings_ParseSettings(t *testing.T) {
    // 	cfg := `
    // # default settings for sessions
    // [DEFAULT]
    // ConnectionType=initiator
    // ReconnectInterval=60
    // SenderCompID=TW

    // # session definition
    // [SESSION]
    // # inherit ConnectionType, ReconnectInterval and SenderCompID from default

    // BeginString=FIX.4.1
    // TargetCompID=ARCA
    // StartTime=12:30:00
    // EndTime=23:30:00
    // HeartBtInt=20
    // SocketConnectPort=9823
    // SocketConnectHost=123.123.123.123
    // DataDictionary=somewhere/FIX41.xml

    // [SESSION]
    // BeginString=FIX.4.0
    // TargetCompID=ISLD
    // StartTime=12:00:00
    // EndTime=23:00:00
    // HeartBtInt=30
    // SocketConnectPort=8323
    // SocketConnectHost=23.23.23.23
    // DataDictionary=somewhere/FIX40.xml

    // [SESSION]
    // BeginString=FIX.4.2
    // SenderSubID=TWSub
    // SenderLocationID=TWLoc
    // TargetCompID=INCA
    // TargetSubID=INCASub
    // TargetLocationID=INCALoc
    // StartTime=12:30:00
    // EndTime=21:30:00
    // # overide default setting for RecconnectInterval
    // ReconnectInterval=30
    // HeartBtInt=30
    // SocketConnectPort=6523
    // SocketConnectHost=3.3.3.3
    // # (optional) alternate connection ports and hosts to cycle through on failover
    // SocketConnectPort1=8392
    // SocketConnectHost1=8.8.8.8
    // SocketConnectPort2=2932
    // SocketConnectHost2=12.12.12.12
    // DataDictionary=somewhere/FIX42.xml
    // `

    // 	stringReader := strings.NewReader(cfg)
    // 	s, err := ParseSettings(stringReader)
    // 	assert.Nil(t, err)
    // 	assert.NotNil(t, s)

    // 	var globalTCs = []struct {
    // 		setting  string
    // 		expected string
    // 	}{
    // 		{"ConnectionType", "initiator"},
    // 		{"ReconnectInterval", "60"},
    // 		{"SenderCompID", "TW"},
    // 	}

    // 	globalSettings := s.GlobalSettings()
    // 	for _, tc := range globalTCs {
    // 		actual, err := globalSettings.Setting(tc.setting)
    // 		assert.Nil(t, err)

    // 		assert.Equal(t, tc.expected, actual)
    // 	}

    // 	sessionSettings := s.SessionSettings()
    // 	assert.Len(t, sessionSettings, 3)

    // 	sessionID1 := SessionID{BeginString: "FIX.4.1", SenderCompID: "TW", TargetCompID: "ARCA"}
    // 	sessionID2 := SessionID{BeginString: "FIX.4.0", SenderCompID: "TW", TargetCompID: "ISLD"}
    // 	sessionID3 := SessionID{
    // 		BeginString:  "FIX.4.2",
    // 		SenderCompID: "TW", SenderSubID: "TWSub", SenderLocationID: "TWLoc",
    // 		TargetCompID: "INCA", TargetSubID: "INCASub", TargetLocationID: "INCALoc"}

    // 	var sessionTCs = []struct {
    // 		sessionID SessionID
    // 		setting   string
    // 		expected  string
    // 	}{
    // 		{sessionID1, "ConnectionType", "initiator"},
    // 		{sessionID1, "ReconnectInterval", "60"},
    // 		{sessionID1, "SenderCompID", "TW"},
    // 		{sessionID1, "BeginString", "FIX.4.1"},
    // 		{sessionID1, "TargetCompID", "ARCA"},
    // 		{sessionID1, "StartTime", "12:30:00"},
    // 		{sessionID1, "EndTime", "23:30:00"},
    // 		{sessionID1, "HeartBtInt", "20"},
    // 		{sessionID1, "SocketConnectPort", "9823"},
    // 		{sessionID1, "SocketConnectHost", "123.123.123.123"},
    // 		{sessionID1, "DataDictionary", "somewhere/FIX41.xml"},

    // 		{sessionID2, "ConnectionType", "initiator"},
    // 		{sessionID2, "ReconnectInterval", "60"},
    // 		{sessionID2, "SenderCompID", "TW"},
    // 		{sessionID2, "BeginString", "FIX.4.0"},
    // 		{sessionID2, "TargetCompID", "ISLD"},
    // 		{sessionID2, "StartTime", "12:00:00"},
    // 		{sessionID2, "EndTime", "23:00:00"},
    // 		{sessionID2, "HeartBtInt", "30"},
    // 		{sessionID2, "SocketConnectPort", "8323"},
    // 		{sessionID2, "SocketConnectHost", "23.23.23.23"},
    // 		{sessionID2, "DataDictionary", "somewhere/FIX40.xml"},

    // 		{sessionID3, "ConnectionType", "initiator"},
    // 		{sessionID3, "BeginString", "FIX.4.2"},
    // 		{sessionID3, "SenderCompID", "TW"},
    // 		{sessionID3, "TargetCompID", "INCA"},
    // 		{sessionID3, "StartTime", "12:30:00"},
    // 		{sessionID3, "EndTime", "21:30:00"},
    // 		{sessionID3, "ReconnectInterval", "30"},
    // 		{sessionID3, "HeartBtInt", "30"},
    // 		{sessionID3, "SocketConnectPort", "6523"},
    // 		{sessionID3, "SocketConnectHost", "3.3.3.3"},
    // 		{sessionID3, "SocketConnectPort1", "8392"},
    // 		{sessionID3, "SocketConnectHost1", "8.8.8.8"},
    // 		{sessionID3, "SocketConnectPort2", "2932"},
    // 		{sessionID3, "SocketConnectHost2", "12.12.12.12"},
    // 		{sessionID3, "DataDictionary", "somewhere/FIX42.xml"},
    // 	}

    // 	for _, tc := range sessionTCs {
    // 		settings, ok := sessionSettings[tc.sessionID]
    // 		require.True(t, ok, "No Session recalled for %v", tc.sessionID)
    // 		actual, err := settings.Setting(tc.setting)

    // 		assert.Nil(t, err)
    // 		assert.Equal(t, tc.expected, actual)
    // 	}
    // }

    // func TestSettings_ParseSettings_WithEqualsSignInValue(t *testing.T) {
    // 	s, err := ParseSettings(strings.NewReader(`
    // [DEFAULT]
    // ConnectionType=initiator
    // SQLDriver=mysql
    // SQLDataSourceName=root:root@/quickfix?parseTime=true&loc=UTC

    // [SESSION]
    // BeginString=FIX.4.2
    // SenderCompID=SENDER
    // TargetCompID=TARGET`))

    // 	require.Nil(t, err)
    // 	require.NotNil(t, s)

    // 	sessionSettings := s.SessionSettings()[SessionID{BeginString: "FIX.4.2", SenderCompID: "SENDER", TargetCompID: "TARGET"}]
    // 	val, err := sessionSettings.Setting("SQLDataSourceName")
    // 	assert.Nil(t, err)
    // 	assert.Equal(t, `root:root@/quickfix?parseTime=true&loc=UTC`, val)
    // }

    // func TestSettings_SessionIDFromSessionSettings(t *testing.T) {
    // 	var testCases = []struct {
    // 		globalBeginString   string
    // 		globalTargetCompID  string
    // 		globalSenderCompID  string
    // 		sessionBeginString  string
    // 		sessionTargetCompID string
    // 		sessionSenderCompID string
    // 		sessionQualifier    string
    // 		expectedSessionID   SessionID
    // 	}{
    // 		{globalBeginString: "FIX.4.0", globalTargetCompID: "CB", globalSenderCompID: "SS",
    // 			expectedSessionID: SessionID{BeginString: "FIX.4.0", TargetCompID: "CB", SenderCompID: "SS"}},

    // 		{sessionBeginString: "FIX.4.1", sessionTargetCompID: "GE", sessionSenderCompID: "LE",
    // 			expectedSessionID: SessionID{BeginString: "FIX.4.1", TargetCompID: "GE", SenderCompID: "LE"}},

    // 		{globalBeginString: "FIX.4.2", globalTargetCompID: "CB", sessionTargetCompID: "GE", sessionSenderCompID: "LE", sessionQualifier: "J",
    // 			expectedSessionID: SessionID{BeginString: "FIX.4.2", TargetCompID: "GE", SenderCompID: "LE", Qualifier: "J"}},
    // 	}

    // 	for _, tc := range testCases {
    // 		globalSettings := NewSessionSettings()
    // 		sessionSettings := NewSessionSettings()

    // 		if tc.globalBeginString != "" {
    // 			globalSettings.Set(config.BeginString, tc.globalBeginString)
    // 		}

    // 		if tc.sessionBeginString != "" {
    // 			sessionSettings.Set(config.BeginString, tc.sessionBeginString)
    // 		}

    // 		if tc.globalTargetCompID != "" {
    // 			globalSettings.Set(config.TargetCompID, tc.globalTargetCompID)
    // 		}

    // 		if tc.sessionTargetCompID != "" {
    // 			sessionSettings.Set(config.TargetCompID, tc.sessionTargetCompID)
    // 		}

    // 		if tc.globalSenderCompID != "" {
    // 			globalSettings.Set(config.SenderCompID, tc.globalSenderCompID)
    // 		}

    // 		if tc.sessionSenderCompID != "" {
    // 			sessionSettings.Set(config.SenderCompID, tc.sessionSenderCompID)
    // 		}

    // 		if len(tc.sessionQualifier) > 0 {
    // 			sessionSettings.Set(config.SessionQualifier, tc.sessionQualifier)
    // 		}

    // 		actualSessionID := sessionIDFromSessionSettings(globalSettings, sessionSettings)

    // 		if tc.expectedSessionID != actualSessionID {
    // 			t.Errorf("Expected %v, got %v", tc.expectedSessionID, actualSessionID)
    // 		}
    // 	}
    // }
}
